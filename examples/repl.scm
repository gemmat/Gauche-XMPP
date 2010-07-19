(use sxml.sxpath)
(use rfc.xmpp)

(define-constant hostname "localhost")
(define-constant yourname "romeo")
(define-constant yourpass "passwd")
(define-constant yourrsrc "Home")
(define-constant message@from (if-car-sxpath '(jabber:client:message @ from *text*)))
(define-constant message-body (if-car-sxpath '(jabber:client:message jabber:client:body *text*)))

(define (my-reader c)
  (call/cc
   (lambda (return)
     (while #t
       (and-let* ((stanza (xmpp-receive-stanza c))
                  (from (message@from stanza))
                  (body (message-body stanza)))
         (return from (read-from-string body)))))))

(define (my-eval expr)
  (guard (e (else (condition-ref e 'message)))
    (eval expr (interaction-environment))))

(define (my-printer-factory c from)
  (lambda args
    (for-each (lambda (expr)
                (xmpp-message (c :to from)
                  `(body ,(write-to-string expr print))))
              args)))

(define (main args)
  (call-with-xmpp-connection hostname
    (lambda (c)
      (xmpp-auth c yourname yourpass)
      (xmpp-bind c yourrsrc)
      (xmpp-session c)
      (xmpp-presence (c))
      (while #t
        (receive (from expr) (my-reader c)
          (let1 my-printer (my-printer-factory c from)
            (my-printer (my-eval expr)))))
      0)))
