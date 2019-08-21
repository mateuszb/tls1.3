(in-package :tls)

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

(defun write-record (ctx record)
  nil)

(define-binary-type varbytes (size-type)
  (:reader
   (in)
   (loop
      with how-many = (read-value size-type in)
      initially (format t "~a bytes of variable data follow~%" how-many)
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
   (ring-buffer-write-byte-sequence out bytes)))

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
    (t 'generic-handshake)))

(define-binary-class generic-handshake (handshake)
  ((data (raw-bytes :size size))))

(define-binary-class client-hello (handshake)
  ((protocol-version u16 :initform +TLS-1.2+)
   (random-bytes (raw-bytes :size 32) :initform (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
   (session-id legacy-session-id)
   (ciphers cipher-suites)
   (compression compression-methods)
   (extensions tls-extensions)))

(define-binary-type legacy-session-id ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u8 in)
      while (plusp how-many)
      collect (read-value 'u8 in)
      do (decf how-many)))
  (:writer
   (out sid)
   (write-value 'u8 (length sid))
   (loop
      for b in sid
      do (write-value 'u8 out b))))

(define-binary-type cipher-suites ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u16 in)
      do
	(format t "~a bytes of cipher suites follow~%" how-many)
      while (plusp how-many)
      collect (read-value 'u16 in)
      do (decf how-many 2)))
  (:writer
   (out ciphers)
   (write-value 'u16 out (* 2 (length ciphers)))
   (loop
      for cipher in ciphers
      do (write-value 'u16 out cipher))))

(define-binary-type compression-methods ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u8 in)
      while (plusp how-many)
      collect (read-value 'u8 in)
      do (decf how-many)))
  (:writer
   (out compression-methods)
   (loop
      for method in compression-methods
      with how-many = (length compression-methods)
      while (plusp how-many)
      do
	(write-value 'u8 out method)
	(decf how-many))))

(define-binary-type tls-extensions ()
  (:reader
   (in)
   (loop
      with ext = nil
      with how-many = (read-value 'u16 in)
      do
	(format t "~a bytes of tls extensions follow~%" how-many)
      while (plusp how-many)
      do
	(setf ext (read-value 'tls-extension in))
	(decf how-many (+ 4 (slot-value ext 'size)))
      collect ext))
  (:writer
   (out val)
   (error "not implemented")))

(define-tagged-binary-class tls-extension ()
  ((extension-type u16)
   (size u16))
  (:dispatch
   (find-extension-class extension-type)))

(defun find-extension-class (extension-type)
  (case extension-type
    (0 'server-name-extension)
    (10 'supported-groups-extension)
    (13 'signature-scheme-extension)
    (43 'client-supported-versions)
    (44 'cookie-extension)
    (45 'psk-key-exchange-modes-extension)
    (51 'client-key-share-hello)
    (otherwise 'generic-extension)))

(define-binary-class generic-extension (tls-extension)
  ((data (raw-bytes :size size))))

(define-binary-type protocol-versions ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u8 in)
      while (plusp how-many)
      collect (read-value 'u16 in)
      do (decf how-many 2)))
  (:writer
   (out versions)
   (write-value 'u8 out (* 2 (length versions)))
   (loop
      for v in versions
      do (write-value 'u16 out v))))

(define-binary-class client-supported-versions (tls-extension)
  ((versions protocol-versions)))

(define-binary-class cookie-extension (tls-extension)
  ((bytes bytes)))

(define-binary-class server-name ()
  ((name-type u8 :initform 0)
   (hostname (varbytes :size-type 'u16))))

(define-binary-type server-names-list ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u16 in)
      with name = nil
      do
	(format t "~a bytes of server extension follow~%" how-many)
      while (plusp how-many)
      do
	(setf name (read-value 'server-name in))
	(decf how-many (+ 1 2 (length (slot-value name 'hostname))))
      collect name))
  (:writer
   (out namelist)
   (labels
       ((get-host-lengths (x) (+ 1 2 (length (slot-value x 'hostname)))))
     (let ((size (reduce #'+ (mapcar #'get-host-lengths namelist))))
       (write-value 'u16 out size)
       (loop for name in namelist
	  do (write-value 'server-name out name))))))

(define-binary-class server-name-extension (tls-extension)
  ((names server-names-list)))

(define-binary-type signature-scheme-list ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u16 in)
      while (plusp how-many)
      collect (read-value 'u16 in)
      do (decf how-many 2)))
  (:writer
   (out schemes)
   (write-value 'u16 out (* (length schemes) 2))
   (loop for s in schemes do (write-value 'u16 out s))))

(define-binary-class signature-scheme-extension (tls-extension)
  ((signature-schemes signature-scheme-list)))

(define-binary-class key-share ()
  ((named-group u16)
   (key-exchange (varbytes :size-type 'u16))))

(define-binary-type key-share-list ()
  (:reader
   (in)
   (labels
       ((key-share-size (x) (+ 2 2 (length (slot-value x 'key-exchange)))))
    (loop
       with keyshare = nil
       with how-many = (read-value 'u16 in)
       while (plusp how-many)
       do
	 (setf keyshare (read-value 'key-share in))
	 (decf how-many (key-share-size keyshare))
       collect keyshare)))
  (:writer
   (out keys)
   (labels
       ((key-share-size (x) (+ 2 (length (slot-value x 'key-exchange)))))
     (let ((size (reduce #'+ (mapcar #'key-share-size keys))))
       (write-value 'u16 out size)
       (loop for key in keys
	  do (write-value 'key-share out key))))))

(define-binary-class client-key-share-hello (tls-extension)
  ((key-shares key-share-list)))

(define-binary-type named-group-list ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u16 in)
      while (plusp how-many)
      collect (read-value 'u16 in)
      do (decf how-many 2)))
  (:writer
   (out groups)
   (write-value 'u16 out (* 2 (length groups)))
   (loop for g in groups do (write-value 'u16 out g))))

(define-binary-class supported-groups-extension (tls-extension)
  ((named-groups named-group-list)))

(define-binary-class client-psk-key-exchange-extension (tls-extension)
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

(define-binary-type psk-identity-list ()
  (:reader
   (in)
   (labels
       ((identity-size (x) (+ 2 4 (length (slot-value x 'psk-identity)))))
     (loop
	with how-many = (read-value 'u16 in)
	with identity = nil
	while (plusp how-many)
	do
	  (setf identity (read-value 'psk-identity in))
	  (decf how-many (identity-size identity))
	collect identity)))
  (:writer
   (out ids)
   (labels
       ((identity-size (x) (+ 2 4 (length (slot-value x 'psk-identity)))))
     (let ((size (reduce #'+ (mapcar #'identity-size ids))))
       (write-value 'u16 out size)
       (loop for i in ids do (write-value 'psk-identity out i))))))

(define-binary-class offered-psks ()
  ((identities psk-identity-list)
   (binders psk-binder-list)))

(define-binary-type key-exchange-mode-list ()
  (:reader
   (in)
   (loop
      with how-many = (read-value 'u8 in)
      while (plusp how-many)
      collect (read-value 'u8 in)
      do (decf how-many)))
  (:writer
   (out modes)
   (write-value 'u8 out (length modes))
   (loop for m in modes do (write-value 'u8 out m))))

(define-binary-class psk-key-exchange-modes-extension (tls-extension)
  ((key-exchange-modes key-exchange-mode-list)))
