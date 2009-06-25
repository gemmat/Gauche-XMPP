#!/usr/bin/env gosh

(use sxml.serializer)
(use rfc.xmpp)

(define-constant hostname     "localhost")
(define-constant yourname     "romeo")
(define-constant yourpass     "romeo")
(define-constant yourresource "Home")

(define (main args)
  (call-with-xmpp-connection hostname
    (lambda (c)
      (xmpp-auth c yourname yourpass)
      (xmpp-bind c yourresource)
      (xmpp-session c)
      (xmpp-presence c)
      (while #t
        (srl:sxml->xml (xmpp-receive-stanza c) (current-output-port))
        (newline)))))

