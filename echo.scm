#!/usr/bin/env gosh

(use sxml.sxpath)
(use rfc.xmpp)

(define-constant hostname     "localhost")
(define-constant yourname     "romeo")
(define-constant yourpass     "romeo")
(define-constant yourresource "Home")

(define (parse-message sxml)
  (and-let* ((from ((if-car-sxpath '(jabber:client:message @ from *text*)) sxml))
             (body ((if-car-sxpath '(jabber:client:message jabber:client:body *text*)) sxml)))
    (cons from body)))

(define (main args)
  (call-with-xmpp-connection hostname
    (lambda (c)
      (xmpp-auth c yourname yourpass)
      (xmpp-bind c yourresource)
      (xmpp-session c)
      (xmpp-presence c)
      (while #t
        (and-let* ((m (parse-message (xmpp-receive-stanza c))))
          (xmpp-message (c :to (car m))
            (cdr m)))))))
