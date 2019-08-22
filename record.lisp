(in-package :tls)

(defvar *mode*)

(define-tagged-binary-class tls-record ()
  ((content-type u8 :initform +RECORD-INVALID+)
   (protocol-version u16 :initform +TLS-1.2+)
   (size u16 :initform 0))
  (:dispatch
   (find-tls-record-class content-type)))

(defun find-tls-record-class (content-type)
  (ecase content-type
    (20 'change-cipher-spec)
    (21 'alert)
    (22 'handshake-record)
    (23 'application-data)
    (24 'heartbeat)))

(define-binary-type varbytes (size-type)
  (:reader
   (in)
   (loop
      with how-many = (read-value size-type in)
      initially (format t "~a bytes of variable data remaining~%" how-many)
      while (plusp how-many)
      collect (read-value 'u8 in)
      do (decf how-many)))
  (:writer
   (out bytes)
   (write-value size-type out (length bytes))
   (loop for b in bytes do (write-value 'u8 out b))))

(define-binary-type raw-bytes (size)
  (:reader
   (in)
   (let ((data (ring-buffer-read-byte-sequence in size)))
     (format t "raw bytes = ~a~%" data)
     data))
  (:writer
   (out bytes)
   (declare (ignorable size))
   (ring-buffer-write-byte-sequence out bytes)))

(define-binary-type tls-list (size-type element-type element-size)
  (:reader
   (in)
   (loop
      with elem = nil
      with how-many = (read-value size-type in)
      do
	(format t "~a bytes ot tls list of ~a remain~%" how-many element-type)
      while (plusp how-many)
      do
	(setf elem (read-value element-type in))
	(format t "element = ~a~%" elem)
	(decf how-many
	      (etypecase element-size
		(function (funcall element-size elem))
		(integer element-size)))
      collect elem))
  (:writer
   (out lst)
   (let ((write-size
	  (etypecase element-size
	    (function (reduce #'+ (mapcar element-size lst)))
	    (integer (* (length lst) element-size)))))
     (write-value size-type out write-size)
     (loop for elem in lst do (write-value element-type out elem)))))

(define-binary-class generic-record (tls-record)
  ((data (raw-bytes :size size))))

(define-binary-class handshake-record (tls-record)
  ((handshake handshake :initform nil)))

(define-tagged-binary-class handshake ()
  ((handshake-type u8 :initform 0)
   (size u24 :initform 0))

  (:dispatch
   (find-handshake-class handshake-type)))

(defun find-handshake-class (handshake-type)
  (ecase handshake-type
    (1 'client-hello)
    (2 'server-hello)))

(define-binary-class generic-handshake (handshake)
  ((data (raw-bytes :size size))))

(defun tls-extension-size (ext)
  (format t "size of ~a is = ~a~%" ext (slot-value ext 'size))
  (+ 2 2 (slot-value ext 'size)))

(define-tagged-binary-class tls-extension ()
  ((extension-type u16)
   (size u16))
  (:dispatch
   (case *mode*
     (:CLIENT (find-client-extension-class extension-type))
     (:SERVER (find-server-extension-class extension-type)))))

(defun find-client-extension-class (extension-type)
  (case extension-type
    (0 'server-name-ext)
    (10 'supported-groups)
    (13 'signature-schemes)
    (43 'client-supported-versions)
    (44 'cookie)
    (45 'psk-key-exchange-modes)
    (51 'client-hello-key-share)
    (otherwise 'generic-extension)))

(defun find-server-extension-class (extension-type)
  (case extension-type
    (0 'server-name-ext)
    (10 'supported-groups)
    (13 'signature-schemes)
    (43 'server-supported-versions)
    (44 'cookie-extension)
    (45 'psk-key-exchange-modes)
    (51 'server-hello-key-share)
    (otherwise 'generic-extension)))

(define-binary-class generic-extension (tls-extension)
  ((data (raw-bytes :size size))))

(define-binary-class client-supported-versions (tls-extension)
  ((versions (tls-list :size-type 'u8
		       :element-type 'u16
		       :element-size 2))))

(define-binary-class server-supported-versions (tls-extension)
  ((version u16)))

(define-binary-class cookie (tls-extension)
  ((bytes bytes)))

(define-binary-class server-name ()
  ((name-type u8 :initform 0)
   (hostname (varbytes :size-type 'u16))))

(defun server-name-size (x)
  (+ 1 2 (length (slot-value x 'hostname))))

(define-binary-class server-name-ext (tls-extension)
  ((names (tls-list :size-type 'u16
		    :element-type 'server-name
		    :element-size #'server-name-size))))

(define-binary-class signature-schemes (tls-extension)
  ((signature-schemes (tls-list :size-type 'u16
				:element-type 'u16
				:element-size 2))))

(defun key-share-size (x)
  (+ 2 2 (length (slot-value x 'key-exchange))))

(define-binary-class key-share ()
  ((named-group u16)
   (key-exchange (varbytes :size-type 'u16))))

(define-binary-class client-hello-key-share (tls-extension)
  ((key-shares (tls-list :size-type 'u16
			 :element-type 'key-share
			 :element-size #'key-share-size))))

(define-binary-class server-hello-key-share (tls-extension)
  ((key key-share)))

(define-binary-class supported-groups (tls-extension)
  ((named-groups (tls-list :size-type 'u16 :element-type 'u16 :element-size 2))))

(define-binary-class client-psk-key-exchange (tls-extension)
  ((offered-psks offered-psks)))

(define-binary-type psk-binder-list ()
  (:reader
   (in)
   (loop
      with binder = nil
      with how-many = (read-value 'u16 in)
      while (plusp how-many)
      do
	(setf binder (read-value 'varbytes in))
	(decf how-many (1+ (length binder)))
      collect binder))
  (:writer
   (out binders)
   (labels ((binder-size (x) (1+ (length x))))
     (let ((size (reduce #'+ (mapcar #'binder-size binders))))
       (write-value 'u16 out size)
       (loop for b in binders do (write-value 'varbytes out b))))))

(define-binary-class psk-identity ()
  ((psk-identity (varbytes :size-type 'u16))
   (obfuscated-ticket-age u32)))

(defun psk-identity-size (x)
  (+ 2 4 (length (slot-value x 'psk-identity))))

(define-binary-class offered-psks ()
  ((identities (tls-list :size-type 'u16 :element-type 'psk-identity
			 :element-size #'psk-identity-size))
   (binders psk-binder-list)))

(define-binary-class psk-key-exchange-modes (tls-extension)
  ((key-exchange-modes (tls-list :size-type 'u8
				 :element-type 'u8
				 :element-size 1))))


(define-binary-class client-hello (handshake)
  ((protocol-version u16 :initform +TLS-1.2+)
   (random-bytes (raw-bytes :size 32) :initform
		 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
   (session-id (tls-list :size-type 'u8 :element-type 'u8 :element-size 1))
   (ciphers (tls-list :size-type 'u16 :element-type 'u16 :element-size 2))
   (compression (tls-list :size-type 'u8 :element-type 'u8 :element-size 1))
   (extensions (tls-list :size-type 'u16
			 :element-type 'tls-extension
			 :element-size #'tls-extension-size))))

(define-binary-class server-hello (handshake)
  ((protocol-version u16 :initform +TLS-1.2+)
   (random-bytes (raw-bytes :size 32)
		 :initform (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
   (session-id (tls-list :size-type 'u8 :element-type 'u8 :element-size 1))
   (selected-cipher u16)
   (compression u8)
   (extensions (tls-list :size-type 'u16
			 :element-type 'tls-extension
			 :element-size #'tls-extension-size))))
