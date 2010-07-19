(use rfc.xmpp)

(define-constant hostname "localhost")
(define-constant yourname "romeo")
(define-constant yourpass "passwd")
(define-constant yourrsrc "Home")

(define (main args)
  (call-with-xmpp-connection hostname
    (lambda (c)
      (xmpp-auth c yourname yourpass)
      (xmpp-bind c yourrsrc)
      (xmpp-session c)
      (xmpp-presence (c))
      (while #t
        (print (xmpp-receive-stanza c)))
      0)))
