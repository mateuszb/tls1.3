(in-package :tls)

(defconstant +RECORD-INVALID+ 0)
(defconstant +RECORD-CHANGE-CIPHER-SPEC+ 20)
(defconstant +RECORD-ALERT+ 21)
(defconstant +RECORD-HANDSHAKE+ 22)
(defconstant +RECORD-APPLICATION-DATA+ 23)
(defconstant +RECORD-HEARTBEAT+ 24)

(defconstant +server-name+ 0)
(defconstant +max-fragment-length+ 1)
(defconstant +status-request+ 5)
(defconstant +supported-groups+ 10)
(defconstant +ec-point-formats+ 11)
(defconstant +signature-algorithms+ 13)
(defconstant +use-srtp+ 14)
(defconstant +heartbeat+ 15)
(defconstant +application-layer-protocol-negotiation+ 16)
(defconstant +signed-certificate-timestamp+ 18)
(defconstant +client-certificate-type+ 19)
(defconstant +server-certificate-type+ 20)
(defconstant +padding+ 21)
(defconstant +pre-shared-key+ 41)
(defconstant +early-data+ 42)
(defconstant +supported-versions+ 43)
(defconstant +cookie+ 44)
(defconstant +psk-key-exchange-modes+ 45)
(defconstant +certificate-authorities+ 46)
(defconstant +oid-filters+ 48)
(defconstant +post-handshake-auth+ 49)
(defconstant +signature-algorithms-cert+ 50)
(defconstant +key-share+ 51)

(defconstant +TLS-1.0+ #x0301)
(defconstant +TLS-1.1+ #x0302)
(defconstant +TLS-1.2+ #x0303)
(defconstant +TLS-1.3+ #x0304)

(defconstant +TLS-AES-128-GCM-SHA256+ #x1301)
(defconstant +TLS-AES-256-GCM-SHA384+ #x1302)
(defconstant +TLS-CHACHA20-POLY1305-SHA256+ #x1303)
(defconstant +TLS-AES-128-CCM-SHA256+ #x1304)
(defconstant +TLS-AES-128-CCM-8-SHA256+ #x1305)

;; TLS 1.2 cipher suites
(defconstant +TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384+ #xC030)
(defconstant +TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256+ #xC02B)
(defconstant +TLS-RSA-WITH-AES-256-CBC-SHA256+ #x003D)
(defconstant +TLS-RSA-WITH-AES-128-CBC-SHA+ #x002F)

(defconstant +TLS-DHE-RSA-WITH-AES-256-CBC-SHA256+ #x006B)


(defconstant +CLIENT-HELLO+ 1)
(defconstant +SERVER-HELLO+ 2)
(defconstant +NEW-SESSION-TICKET+ 4)
(defconstant +END-OF-EARLY-DATA+ 5)
(defconstant +ENCRYPTED-EXTENSIONS+ 8)
(defconstant +CERTIFICATE+ 11)
(defconstant +CERTIFICATE-REQUEST+ 13)
(defconstant +CERTIFICATE-VERIFY+ 15)
(defconstant +FINISHED+ 20)
(defconstant +KEY-UPDATE+ 24)
(defconstant +MESSAGE-HASH+ 254)

;; signature algorithms
(defconstant +rsa-pkcs1-sha256+ #x0401)
(defconstant +rsa-pkcs1-sha384+ #x0501)
(defconstant +rsa-pkcs1-sha512+ #x0601)

(defconstant +ecdsa-secp256r1-sha256+ #x0403)
(defconstant +ecdsa-secp384r1-sha384+ #x0503)
(defconstant +ecdsa-secp521r1-sha512+ #x0603)

(defconstant +rsa-pss-rsae-sha256+ #x0804)
(defconstant +rsa-pss-rsae-sha384+ #x0805)
(defconstant +rsa-pss-rsae-sha512+ #x0806)

(defconstant +ed25519+ #x0807)
(defconstant +ed448+ #x0808)

(defconstant +rsa-pss-pss-sha256+ #x0809)
(defconstant +rsa-pss-pss-sha384+ #x080a)
(defconstant +rsa-pss-pss-sha512+ #x080b)

;; elliptic curve groups (ECDHE)
(defconstant +secp256r1+ #x0017)
(defconstant +secp384r1+ #x0018)
(defconstant +secp521r1+ #x0019)
(defconstant +x25519+ #x001d)
(defconstant +x448+ #x001e)

;; finite fieldgroups (DHE)
(defconstant +ffdhe2048+ #x0100)
(defconstant +ffdhe3072+ #x0101)
(defconstant +ffdhe4096+ #x0102)
(defconstant +ffdhe6144+ #x0103)
(defconstant +ffdhe8192+ #x0104)

(defparameter +HELLO-RETRY-REQUEST-RANDOM+
  #(207 33 173 116 229 154 97 17 190 29 140 2 30 101 184 145 194 162 17 22 122
  187 140 94 7 158 9 226 200 168 51 156))

;; ALERT related constants

(defconstant +ALERT-WARNING+ 1)
(defconstant +ALERT-FATAL+ 2)

(defconstant +close-notify+ 0)
(defconstant +unexpected-message+ 10)
(defconstant +bad-record-mac+ 20)
(defconstant +record-overflow+ 22)
(defconstant +handshake-failure+ 40)
(defconstant +bad-certificate+ 42)
(defconstant +unsupported-certificate+ 43)
(defconstant +certificate-revoked+ 44)
(defconstant +certificate-expired+ 45)
(defconstant +certificate-unknown+ 46)
(defconstant +illegal-parameter+ 47)
(defconstant +unknown-ca+ 48)
(defconstant +access-denied+ 49)
(defconstant +decode-error+ 50)
(defconstant +decrypt-error+ 51)
(defconstant +protocol-version+ 70)
(defconstant +insufficient-security+ 71)
(defconstant +internal-error+ 80)
(defconstant +inappropriate-fallback+ 86)
(defconstant +user-canceled+ 90)
(defconstant +missing-extension+ 109)
(defconstant +unsupported-extension+ 110)
(defconstant +unrecognized-name+ 112)
(defconstant +bad-certificate-status-response+ 113)
(defconstant +unknown-psk-identity+ 115)
(defconstant +certificate-required+ 116)
(defconstant +no-application-protocol+ 120)
