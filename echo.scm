(use sxml.sxpath)
(use rfc.xmpp)

(define-constant hostname "localhost")
(define-constant yourname "romeo")
(define-constant yourpass "passwd")
(define-constant yourrsrc "Home")
(define-constant message@from (if-car-sxpath '(jabber:client:message @ from *text*)))
(define-constant message-body (if-car-sxpath '(jabber:client:message jabber:client:body *text*)))

(define (main args)
  (call-with-xmpp-connection hostname
    (lambda (c)
      (xmpp-auth c yourname yourpass)
      (xmpp-bind c yourrsrc)
      (xmpp-session c)
      (xmpp-presence (c))
      (while #t
        (and-let* ((stanza (xmpp-receive-stanza c))
                   (from (message@from stanza))
                   (body (message-body stanza)))
          (xmpp-message (c :to from)
            `(body ,body))))
      0)))
