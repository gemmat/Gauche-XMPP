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

(define (my-reader c)
  (let loop ()
    (let1 m (parse-message (xmpp-receive-stanza c))
      (if m
        (values (car m) (read-from-string (cdr m)))
        (loop)))))

(define (my-printer-factory c from)
  (lambda args
    (for-each (lambda (expr)
                (xmpp-message (c :to from)
                  (write-to-string expr print)))
              args)))

(define (main args)
  (call-with-xmpp-connection hostname
    (lambda (c)
      (xmpp-auth c yourname yourpass)
      (xmpp-bind c yourresource)
      (xmpp-session c)
      (xmpp-presence c)
      (while #t
        (receive (from expr) (my-reader c)
          (let1 my-printer (my-printer-factory c from)
            (my-printer (guard (e
                                (else (condition-ref e 'message)))
                               (eval expr (interaction-environment))))))))))
          
