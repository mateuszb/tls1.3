(in-package :tls)

(define-tagged-binary-class tls-record ()
  ((content-type u8 :initform +RECORD-INVALID+)
   (protocol-version u16 :initform +TLS-1.2+)
   (size u16 :initform 0)
   (message generic-record :initform nil))
  (:dispatch
   (find-tls-record-class content-type)))

(defun find-tls-record-class (content-type)
  (ecase content-type
    (+RECORD-CHANGE-CIPHER-SPEC+ 'change-cipher-spec)
    (+RECORD-ALERT+ 'alert)
    (+RECORD-HANDSHAKE+ 'handshake)
    (+RECORD-APPLICATION-DATA+ 'application-data)
    (+RECORD-HEARTBEAT+ 'heartbeat)
    (t 'generic-record)))

(defun write-record (ctx record)
  nil)

(define-binary-type raw-bytes (size)
  (:reader (in)
	   (ring-buffer-read-byte-sequence in size))
  (:writer (out bytes)
	   (ring-buffer-write-byte-sequence out bytes)))

(define-binary-class generic-record (tls-record)
  ((data (raw-bytes :size size))))

(define-tagged-binary-class tls-message ()
  (()))
