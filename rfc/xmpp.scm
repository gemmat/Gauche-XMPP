;;;
;;; xmpp.scm - XMPP(RFC3920, RFC3921) client library for the Gauche.
;;;
;;; rfc.xmpp
;;;
;;; Copyright (c) 2005 Erik Enge(erik.enge@gmail.com)
;;;               2009 Teruaki Gemma(teruakigemma@gmail.com)
;;;
;;; Permission is hereby granted, free of charge, to any person obtaining
;;; a copy of this software and associated documentation files (the
;;; "Software"), to deal in the Software without restriction, including
;;; without limitation the rights to use, copy, modify, merge, publish,
;;; distribute, sublicense, and/or sell copies of the Software, and to
;;; permit persons to whom the Software is furnished to do so, subject to
;;; the following conditions:
;;;
;;; The above copyright notice and this permission notice shall be
;;; included in all copies or substantial portions of the Software.
;;;
;;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;;; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;;; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;;; NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
;;; LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
;;; OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
;;; WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
;;;
;;;  $Id$
;;;

;;; This library includes some codes from cl-xmpp version 0.8.1
;;; (http://common-lisp.net/project/cl-xmpp/) released under the MIT-style license.
;;; Thanks cl-xmpp developers.

(define-module rfc.xmpp
  (use srfi-1)
  (use srfi-13)
  (use util.list)
  (use gauche.net)
  (use gauche.uvector)
  (use sxml.ssax)
  (use sxml.sxpath)
  (use sxml.tools)
  (use sxml.serializer)
  (use rfc.md5)
  (use rfc.base64)  
  (use math.mt-random)
  (export <xmpp-connection>
          xmpp-connect
          xmpp-disconnect
          xmpp-receive-stanza
          xmpp-iq
          xmpp-iq-query
          xmpp-discover
          xmpp-registration-requirements
          xmpp-register
          xmpp-cancel-registration
          xmpp-change-password
          xmpp-auth-select-mechanism
          xmpp-auth-requirements
          xmpp-bind
          xmpp-session
          xmpp-presence
          xmpp-message
          xmpp-request-subscription
          xmpp-approve-subscription
          xmpp-unsubscribe
          xmpp-cancel-registration
          xmpp-get-roster
          xmpp-roster-add
          xmpp-roster-remove
          xmpp-get-privacy-lists
          xmpp-get-privacy-list
          xmpp-auth
          xmpp-sasl-anonymous
          xmpp-sasl-plain
          xmpp-sasl-digest-md5
          )
  )

(select-module rfc.xmpp)

(define *default-port* 5222)

(define (RES-NAME->SXML res-name)
  (string->symbol
   (string-append
    (symbol->string (car res-name))
    ":"
    (symbol->string (cdr res-name)))))

(define (FINISH-ELEMENT elem-gi attributes namespaces parent-seed seed)
  (let ((seed (ssax:reverse-collect-str-drop-ws seed))
        (attrs (attlist-fold (lambda (attr accum)
                               (cons (list
                                      (if (symbol? (car attr)) (car attr)
                                          (RES-NAME->SXML (car attr)))
                                      (cdr attr)) accum))
                             '()
                             attributes)))
    (cons
     (cons
      (if (symbol? elem-gi) elem-gi
          (RES-NAME->SXML elem-gi))
      (if (null? attrs) seed
          (cons (cons '@ attrs) seed)))
     parent-seed)))

(define elem-parser (ssax:make-elem-parser
                     (lambda (elem-gi attributes namespaces expected-content seed)
                       '())
                     FINISH-ELEMENT
                     (lambda (string1 string2 seed)
                       (if (string=? "" string2)
                         (cons string1 seed)
                         (cons* string2 string1 seed)))
                     ()))

#|
"A TCP connection between this XMPP client and
an, assumed, XMPP compliant server.  The connection does not
know whether or not the XML stream has been initiated nor whether
there may be any reply waiting to be read from the stream.  These
details are left to the programmer."
|#

#|
stream-id:   Stream ID attribute of the <stream> element as
             gotten when we call BEGIN-XML-STREAM.
features:    List of xml-element objects representing the various features
             the host at the other end of the connection supports.
mechanisms:  List of xml-element objects representing the various mechainsms
             the host at the other end of the connection will accept.
|#

(define-class <xmpp-connection> ()
  ((socket          :init-keyword :socket)
   (socket-iport    :init-keyword :socket-iport)
   (socket-oport    :init-keyword :socket-oport)
   (stream-id)
   (stream-default-namespace)
   (features)
   (jid-domain-part :init-keyword :jid-domain-part)
   (hostname        :init-keyword :hostname)
   (port            :init-keyword :port)
   (channel         :init-form (channel-essential-table))))

(define-method write-object ((conn <xmpp-connection>) out)
  (format out "<connection to ~A:~A> ~A"
          (ref conn 'hostname)
          (ref conn 'port)
          (socket-status (ref conn 'socket))))

;;
;; Channel
;;
;; hash-table. key=xpath, value=handler.

(define (channel-essential-table)
  (define (handle-stream conn sxml)
    (set! (ref conn 'stream-id) ((if-car-sxpath '(http://etherx.jabber.org/streams:stream @ id *text*)) sxml)))
  (define (handle-features conn sxml)
    (set! (ref conn 'features)   ((sxpath '(http://etherx.jabber.org/streams:features *)) sxml)))

  `((((http://etherx.jabber.org/streams:stream))   . ,handle-stream)
    (((http://etherx.jabber.org/streams:features)) . ,handle-features)))

(define (xmpp-connect hostname . args)
  (let-keywords args ((port             *default-port*)
                      (jid-domain-part   #f))
    (let* ((socket (make-client-socket 'inet hostname port))
           (conn (make <xmpp-connection>
                   :socket          socket
                   :socket-iport   (socket-input-port  socket :buffering :none)
                   :socket-oport   (socket-output-port socket)
                   :hostname        hostname
                   :port            port
                   :jid-domain-part jid-domain-part)))
      (begin-xml-stream conn)
      (xmpp-receive-stanza conn) ; stream
      (xmpp-receive-stanza conn) ; features
      conn)))

(define-method xmpp-disconnect ((conn <xmpp-connection>))
  (end-xml-stream conn)
  (let ((s (ref conn 'socket)))
    (socket-close s)
    (socket-shutdown s SHUT_RDWR)))

(define-method xmpp-receive-stanza ((conn <xmpp-connection>))
  (define (read-stanza conn)
    (guard (e (else (format (current-error-port) "Error: ~a\n" (condition-ref e 'message))
                    (xmpp-disconnect conn)))
      (let ((inp (ref conn 'socket-iport)))
        (call/cc
         (lambda (return)
           (while #t
             (when (char-ready? inp)
               (receive (_ token) (ssax:read-char-data inp #t (lambda _ #t) #t)
                 (cond
                  ((eof-object? token)
                   (error "The connection closed by peer."))
                  ((equal? token '(START . (stream . stream))) ;; <stream:stream> XMPP stream start.
                   (receive
                       (elem-gi attributes namespaces elem-content-model)
                       (ssax:complete-start-tag '(stream . stream) inp #f '() '())
                     (set! (ref conn 'stream-default-namespace) namespaces)
                     (return (cons '*TOP* (FINISH-ELEMENT elem-gi attributes namespaces '() '())))))
                  ((equal? token '(END . (stream . stream)))   ;;</stream:stream> XMPP stream end.
                   (return '(end-tag-of-stream)))
                  ((eq? 'PI (xml-token-kind token))
                   ;; if you need to process the xml PI, try a following line.
                   ;;`(*PI* ,(xml-token-head token) ,(ssax:read-pi-body-as-string inp)))
                   (ssax:skip-pi inp))
                  ((eq? 'START (xml-token-kind token))
                   (return (cons '*TOP* (elem-parser (xml-token-head token) inp #f '()
                                                     (ref conn 'stream-default-namespace) #f '()))))
                  (else
                   (errorf "Oops. What's happened? ~a" (read-char inp))))))))))))
    
  (flush (ref conn 'socket-oport))
  (let1 stanza (read-stanza conn)
    (for-each (lambda (x)
                (let ((xpath   (car x))
                      (handler (cdr x)))
                  (when ((if-sxpath xpath) stanza)
                    (handler conn stanza))))
              (ref conn 'channel))
    stanza))

(define-syntax with-output-to-connection
  (syntax-rules ()
    ((_ conn body ...)
     (with-output-to-port (ref conn 'socket-oport)
       (lambda ()
         body
         ...
         (flush))))))

(define (print-sxml sxml)
  (srl:sxml->xml sxml (current-output-port)))

;;
;; Operators for communicating over the XML stream
;;

;;"Begin XML stream.  This should be the first thing to happen on a
;; newly connected connection."

(define-method begin-xml-stream ((conn <xmpp-connection>) . args)
  (let-keywords args ((xml-identifier #t))
    (with-output-to-connection conn
      (when xml-identifier
       (print "<?xml version='1.0' ?>"))
      (format #t "<stream:stream to='~a' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
              (or (ref conn 'jid-domain-part) (ref conn 'hostname))))))


;;"Closes the XML stream.  At this point you'd have to
;; call BEGIN-XML-STREAM if you wished to communicate with
;; the server again."
(define-method end-xml-stream ((conn <xmpp-connection>))
  (with-output-to-connection conn
    (print "</stream:stream>")))

;;"Macro to make it easier to write IQ stanzas."
(define-syntax xmpp-iq
  (syntax-rules ()
    ((_ (conn args ...))
     (xmpp-iq (conn args ...) '()))
    ((_ (conn args ...) body)
     (let-keywords (list args ...) ((id #f)
                                    (to #f)
                                    (type "get"))
       (with-output-to-connection conn
         (print-sxml `(iq (|@| ,@(cond-list
                                  (id `(id ,id))
                                  (to `(to ,to))
                                  (#t `(type ,type))))
                          ,body)))))))

;;"Macro to make it easier to write QUERYs."
(define-syntax xmpp-iq-query
  (syntax-rules ()
    ((_ (conn args ...))
     (xmpp-iq-query (conn args ...) '()))
    ((_ (conn args ...) body)
     (let-keywords (list args ...) ((xmlns #f)
                                    (id    #f)
                                    (to    #f)
                                    (node  #f)
                                    (type  "get"))
       (xmpp-iq (conn :id id :type type :to to)
                `(query (|@| ,@(cond-list
                                (xmlns `(xmlns ,xmlns))
                                (node  `(node ,node))))
                        ,@body))))))


;;
;; Discovery
;;

(define-method xmpp-discover ((conn <xmpp-connection>) . args)
  (let-keywords args ((type :info)
                      (to #f)
                      (node #f))
    (let ((xmlns (case type
                   ((:info)  "http://jabber.org/protocol/disco#info")
                   ((:items) "http://jabber.org/protocol/disco#items")
                   (else (error "Unknown type: ~a (Please choose between :info and :items)" type)))))
      (xmpp-iq-query (conn :id "info1" :xmlns xmlns :to to :node node)))))

;;
;; Basic operations
;;

(define-method xmpp-registration-requirements ((conn <xmpp-connection>))
  (xmpp-iq-query (conn :id "reg1" :xmlns "jabber:iq:register")))

(define-method xmpp-register ((conn <xmpp-connection>) username password name email)
  (xmpp-iq-query (conn :id "reg2" :type "set" :xmlns "jabber:iq:register")
                 `((username ,username)
                   (password ,password)
                   (name     ,name)
                   (email    ,email))))

(define-method xmpp-cancel-registration ((conn <xmpp-connection>))
  (xmpp-iq-query (conn :id "unreg1" :type "set" :xmlns "jabber:iq:register")
                 '((remove))))

(define-method xmpp-change-password ((conn <xmpp-connection>) new-password)
  (xmpp-iq-query (conn :id "change1" :type "set" :xmlns "jabber:iq:register")
                 `((username ,(username conn))
                   (password ,new-password))))

(define-method xmpp-auth-select-mechanism ((conn <xmpp-connection>) mechanism)
  (with-output-to-connection conn
    (print-sxml `(auth (|@| (xmlns "urn:ietf:params:xml:ns:xmpp-sasl")
                            (mechanism ,mechanism))))))

(define-method xmpp-auth-requirements ((conn <xmpp-connection>) username)
  (xmpp-iq-query (conn :id "auth1" :xmlns "jabber:iq:auth")
                 `((username ,username))))

(define-method xmpp-bind ((conn <xmpp-connection>) resource)
  (xmpp-iq (conn :id "bind_2" :type "set")
           `(bind (|@| (xmlns "urn:ietf:params:xml:ns:xmpp-bind"))
                  (resource ,resource))))

(define-method xmpp-session ((conn <xmpp-connection>))
  (xmpp-iq (conn :id "session_1" :type "set")
           `(session
             (|@| (xmlns "urn:ietf:params:xml:ns:xmpp-session")))))

(define-method xmpp-presence ((conn <xmpp-connection>) . args)
  (let-keywords args ((type #f)
                      (to #f)
                      (status #f)
                      (show #f)
                      (priority #f))
    (with-output-to-connection conn
      (print-sxml `(presence (|@| ,@(cond-list
                                     (type     `(type     ,type))
                                     (to       `(to       ,to))
                                     (status   `(status   ,status))
                                     (show     `(show     ,show))
                                     (priority `(priority ,(format #f "~A" priority))))))))))

(define-syntax xmpp-message
  (syntax-rules ()
    ((_ (conn args ...))
     (xmpp-message (conn args ...) ""))
    ((_ (conn args ...) str extra ...)
     (let-keywords (list args ...) ((id #f)
                                    (to #f)
                                    (type "chat")
                                    (lang #f))
       (with-output-to-connection conn       
         (print-sxml `(message (|@| ,@(cond-list
                                       (id   `(id ,id))
                                       (to   `(to ,to))
                                       (type `(type ,(string-downcase type)))
                                       (lang `(xml:lang ,lang))))
                               (body ,str)
                               ,extra ...)))))))

;;
;; Subscription
;;

(define-method xmpp-request-subscription ((conn <xmpp-connection>) to)
  (xmpp-presence conn :type "subscribe"    :to to))

(define-method xmpp-approve-subscription ((conn <xmpp-connection>) to)
  (xmpp-presence conn :type "subscribed"   :to to))

(define-method xmpp-unsubscribe          ((conn <xmpp-connection>) to)
  (xmpp-presence conn :type "unsubscribe"  :to to))

(define-method xmpp-cancel-subscription  ((conn <xmpp-connection>) to)
  (xmpp-presence conn :type "unsubscribed" :to to))


;;
;; Roster
;;

(define-method xmpp-get-roster ((conn <xmpp-connection>))
  (xmpp-iq-query (conn :id "roster_1" :xmlns "jabber:iq:roster")))

;;; Note: Adding and removing from the roster is not the same as
;;; adding and removing subscriptions.  I have not yet decided
;;; if the library should provide convenience methods for doing
;;; both actions at once.
(define-method xmpp-roster-add ((conn <xmpp-connection>) jid name group)
  (xmpp-iq-query (conn :id "roster_2" :type "set" :xmlns "jabber:iq:roster")
                 `((item
                    (|@| (jid ,jid) (name ,name))
                    (group ,group)))))

(define-method xmpp-roster-remove ((conn <xmpp-connection>) jid)
  (xmpp-iq-query (conn :id "roster_4" :type "set" :xmlns "jabber:iq:roster")
                 `((item
                    (|@| (jid ,jid) (subscription "remove"))))))

;;
;; Privacy list
;;

;;; Implemented in Jabberd2 and on which I have not tested with.
(define-method xmpp-get-privacy-lists ((conn <xmpp-connection>))
  (xmpp-iq-query (conn :id "getlist1" :xmlns "jabber:iq:privacy")))

(define-method xmpp-get-privacy-list ((conn <xmpp-connection>) name)
  (xmpp-iq-query (conn :id "getlist2" :xmlns "jabber:iq:privacy")
                 `((list
                    (|@| (name ,name))))))

;; --- SASL Authentication---

(define-method xmpp-auth ((conn <xmpp-connection>) username password)
  (define mechanism-has-digest-md5?
    (if-car-sxpath '(// (urn:ietf:params:xml:ns:xmpp-sasl:mechanism ((equal? "DIGEST-MD5"))))))
  (define mechanism-has-plain?
    (if-car-sxpath '(// (urn:ietf:params:xml:ns:xmpp-sasl:mechanism ((equal? "PLAIN"))))))
  (define mechanism-has-anonymous?
    (if-car-sxpath '(// (urn:ietf:params:xml:ns:xmpp-sasl:mechanism ((equal? "ANONYMOUS"))))))
  
  (let1 features (ref conn 'features)
    (cond ((mechanism-has-digest-md5? features)
           (xmpp-sasl-digest-md5 conn username password))
          ((mechanism-has-plain? features)
           (xmpp-sasl-plain conn username password))
          ((mechanism-has-anonymous? features)
           (xmpp-sasl-anonymous conn)))))

(define (if-successful-restart-stream conn reply)
  (if (eq? (caadr reply) 'urn:ietf:params:xml:ns:xmpp-sasl:success)
    (begin
      (begin-xml-stream conn :xml-identifier #f)
      (xmpp-receive-stanza conn)  ; stream
      (xmpp-receive-stanza conn)  ; features
      :success)
    :failure))

(define-method xmpp-sasl-anonymous ((conn <xmpp-connection>))
  (with-output-to-connection conn
    (print "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='ANONYMOUS'/>"))
  (if-successful-restart-stream conn (xmpp-receive-stanza conn)))
  
(define-method xmpp-sasl-plain ((conn <xmpp-connection>) username password)
  (with-output-to-connection conn
    (format #t "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>~a</auth>"
            (base64-encode-string (string-join `("" ,username ,password) "\u0000"))))
  (if-successful-restart-stream conn (xmpp-receive-stanza conn)))

(define-method xmpp-sasl-digest-md5 ((conn <xmpp-connection>) username password)
  ;; We immediately return when any auth steps have failed.
  (define return #f)
  (define (step1)
    (let1 initial-challenge (xmpp-receive-stanza conn)
      (if (eq? (caadr initial-challenge) 'urn:ietf:params:xml:ns:xmpp-sasl:challenge)
        (let1 challenge-string (base64-decode-string (sxml:string-value initial-challenge))
          (make-digest-md5-response username password (ref conn 'hostname) challenge-string))
        (return initial-challenge))))
  (define (step2 response rspauth-expected)
    (let* ((second-challenge (xmpp-receive-stanza conn))
           (rspauth (assoc-ref (parse-challenge (base64-decode-string (sxml:string-value second-challenge))) "rspauth")))
      (or (and (eq? (caadr second-challenge) 'urn:ietf:params:xml:ns:xmpp-sasl:challenge)
               (string=? rspauth-expected rspauth))
          (return second-challenge))))

  (if-successful-restart-stream
   conn
   (call/cc
    (lambda (cc)
      (set! return cc)
      (with-output-to-connection conn
        (print "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='DIGEST-MD5'/>"))
      (receive (response rspauth) (step1)
        (with-output-to-connection conn
          (format #t "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>~a</response>" (base64-encode-string response)))
        (step2 response rspauth))
      (with-output-to-connection conn
        (print "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"))
      (xmpp-receive-stanza conn)))))

(define (parse-challenge str)
  (filter-map (lambda (x) 
                (and-let* ((p (string-split x "="))
                           ((eq? 2 (length p)))
                           (key (car p))
                           (value (cadr p)))
                  ;; strip double-quotes.
                  (rxmatch-if (#/^\"(.*)\"$/ value)
                      (#f s)
                      (cons key s)
                      (cons key value))))
              (string-split str ",")))

(define (make-digest-md5-response username password hostname challenge)
  (define (dblq str)
    (string-append "\"" str "\""))

  (let1 l (parse-challenge challenge)
    (let ((nonce      (assoc-ref l "nonce"))
          (qop        (assoc-ref l "qop"))
          (charset    (assoc-ref l "charset"))
          (digest-uri (string-append "xmpp/" hostname))
          (cnonce     (make-cnonce))
          (realm      "")
          (nc         "00000001"))
      (let ((rsp              (digest-md5 username #f realm password digest-uri nonce cnonce nc qop #t))
            (rspauth-expected (digest-md5 username #f realm password digest-uri nonce cnonce nc qop #f)))
        (values (string-join (map (cut string-join <> "=")
                                  `(("username"   ,(dblq username))
                                    ("realm"      ,(dblq realm))
                                    ("nonce"      ,(dblq nonce))
                                    ("cnonce"     ,(dblq cnonce))
                                    ("digest-uri" ,(dblq digest-uri))
                                    ("response"   ,rsp)
                                    ("nc"         ,nc)
                                    ("qop"        ,qop)
                                    ("charset"    ,charset)))
                             ",")
                rspauth-expected)))))

(define (make-cnonce)
  (let ((mt (make <mersenne-twister> :seed (sys-time)))
        (uv (make-u32vector 4)))
    (mt-random-fill-u32vector! mt uv)
    (base64-encode-string (u32vector->string uv))))

(define (digest-md5 authc-id authz-id realm password digest-uri nonce cnonce nc qop request)
  (and-let* ((X   (string-join `(,authc-id ,realm ,password) ":"))
             (Y   (md5-digest-string X))
             (A1  (string-join (if authz-id
                                 `(,Y ,nonce ,cnonce ,authz-id)
                                 `(,Y ,nonce ,cnonce))
                               ":"))
             (A2  (string-join `(,(if request
                                    "AUTHENTICATE"
                                    "")
                                 ,digest-uri)
                               ":"))
             (HA1 (digest-hexify (md5-digest-string A1)))
             (HA2 (digest-hexify (md5-digest-string A2)))
             (KD  (string-join `(,HA1 ,nonce ,nc ,cnonce ,qop ,HA2) ":"))
             (Z   (digest-hexify (md5-digest-string KD))))
    Z))

(provide "rfc/xmpp")