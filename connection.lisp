(in-package :tls)

(defvar *connections*)

(defclass tls-connection ()
  ((tlsrx :initform (make-binary-ring-stream 8192) :accessor tls-rx-stream)
   (tlstx :initform (make-binary-ring-stream 8192) :accessor tls-tx-stream)
   (rx :initform (make-binary-ring-stream 8192) :accessor rx-stream)
   (tx :initform (make-binary-ring-stream 8192) :accessor tx-stream)
   (rx-data :initform (make-binary-ring-stream 8192) :accessor rx-data-stream)
   (tx-data :initform (make-binary-ring-stream 8192) :accessor tx-data-stream)
   (records :initform nil :accessor tls-records)
   (state :initform nil :initarg :state :accessor state)
   (pubkey :initform nil :accessor public-key)
   (seckey :initform nil :accessor private-key)
   (peer-pubkey :initform nil :accessor peer-key)
   (handshake-stream :initform (ironclad:make-digesting-stream :sha384) :accessor digest-stream)
   (record-hash :initform nil)
   (shared-secret :initform nil :accessor shared-secret)

   (handshake-secret :initform nil :accessor handshake-secret)

   (my-secret :initform nil :accessor my-handshake-secret)
   (my-hs-key :accessor my-handshake-key)
   (my-hs-iv :accessor my-handshake-iv)

   (peer-hs-secret :accessor peer-handshake-secret)
   (peer-hs-key :accessor peer-handshake-key)
   (peer-hs-iv :accessor peer-handshake-iv)

   (cipher :accessor cipher)
   (hash :accessor hash)
   (key-exchange-mode :accessor key-exchange-mode)

   (master-secret :initform nil :accessor master-secret)

   (my-app-secret :accessor my-app-secret)
   (my-app-key :accessor my-app-key)
   (my-app-iv :accessor my-app-iv)

   (peer-app-secret :accessor peer-app-secret)
   (peer-app-key :accessor peer-app-key)
   (peer-app-iv :accessor peer-app-iv)

   (mode :accessor tls-mode)

   (nonce-in :initform 0 :accessor nonce-in)
   (nonce-out :initform 0 :accessor nonce-out)

   (socket :accessor socket :initform -1 :initarg :socket)
   (certificate :accessor certificate)

   ;; callbacks
   (accept-fn :accessor accept-fn :initarg :accept-fn)
   (read-fn :accessor read-fn :initarg :read-fn)
   (write-fn :accessor write-fn :initarg :write-fn)
   (alert-fn :accessor alert-fn :initarg :alert-fn)
   (disconnect-fn :accessor disconnect-fn :initarg :disconnect-fn)

   ;; overflow transmit queue of 512 slots
   (tx-queue :initform (make-queue 512) :reader tx-queue)

   ;; user data
   (data :accessor data :initarg :data)))

(defclass tls12-connection (tls-connection)
  ())

(defclass tls13-connection (tls-connection)
  ())

(defun make-tls-connection (socket state data accept-fn read-fn write-fn alert-fn disconnect-fn)
  (make-instance 'tls-connection
		 :socket socket :state state
		 :data data
		 :accept-fn accept-fn
		 :read-fn read-fn
		 :write-fn write-fn
		 :alert-fn alert-fn
		 :disconnect-fn disconnect-fn))

(defun upgrade-tls-connection (conn version)
  (ecase version
    (:tls12 (change-class conn 'tls12-connection))
    (:tls13 (change-class conn 'tls13-connection))))

(defun tls-read (tls &optional n)
  (let ((read-size n))
    (unless read-size
      (setf read-size (stream-size (rx-data-stream tls))))
    (let ((seq (make-array read-size :element-type '(unsigned-byte 8) :initial-element 0)))
      (read-sequence seq (rx-data-stream tls))
      seq)))

(defun encrypt-data (tls data &optional (content-type +RECORD-APPLICATION-DATA+))
  (let* ((total-size (1+ (length data)))
	 (aead-data (gen-aead-data total-size))
	 (aead (make-aead-aes256-gcm
		(my-app-key tls)
		(my-app-iv tls)
		(get-out-nonce! tls))))
    (values
     (ironclad:encrypt-message
      aead
      (with-output-to-byte-sequence (out total-size)
	(write-sequence data out)
	(write-value 'u8 out content-type))
      :associated-data aead-data)
     (ironclad:produce-tag aead))))

(defgeneric tls-write (tls seq &optional content-type))

(defmethod tls-write (tls (seq string) &optional (content-type +RECORD-APPLICATION-DATA+))
  (tls-write
   tls
   (map '(simple-array (integer 0 255) (*)) #'char-code seq)
   content-type))

(defmethod tls-write (tls (seq array) &optional (content-type +RECORD-APPLICATION-DATA+))
  (let* ((free-space (stream-space-available (tx-stream tls)))
	 (minsize (+ 1 5 16))
	 (xfer-size 0))
    ;; first, fill out as much space as available in the tx-stream
    (when (> free-space minsize)
      ;; we can send at least 1 byte here and 22 bytes of header, tag
      ;; and content type markers
      (setf xfer-size (min (length seq) (- free-space minsize)))
      (let ((record (make-instance 'tls-record
				   :size (+ 16 1 xfer-size)
				   :content-type content-type)))
	(write-value 'tls-record (tx-stream tls) record)
	(multiple-value-bind (ciphertext authtag)
	    (encrypt-data tls (subseq seq 0 xfer-size))
	  (write-sequence ciphertext (tx-stream tls))
	  (write-sequence authtag (tx-stream tls)))))
    ;; now, enqueue the overflow data into the tx queue
    ;; where the tx loop will periodically fetch it from and send over
    (let ((remaining (subseq seq xfer-size)))
      (enqueue (cons 0 remaining) (tx-queue tls)))
    (on-write (socket tls) #'tls-tx)))

(defun alert->bytes (alert)
  (with-output-to-byte-sequence (out 2)
    (write-value 'alert out alert)))

(defun send-alert (tls level desc)
  (let ((alert (make-instance 'alert :level level :description desc))
	(hdr (make-instance 'tls-record :content-type +RECORD-ALERT+ :size 2)))
    (cond
      ((encrypted-p tls)
       (format t "encrypted alert")
       (let ((record (make-instance 'tls-record :size (+ 16 1 2) :content-type +RECORD-APPLICATION-DATA+)))
	(write-value 'tls-record (tx-stream tls) record)
	(multiple-value-bind (ciphertext authtag)
	    (encrypt-data tls (alert->bytes alert) +RECORD-ALERT+)
	  (write-sequence ciphertext (tx-stream tls))
	  (write-sequence authtag (tx-stream tls)))))
      (t
       (format t "not encrypted alert~%")
       (write-value 'tls-record (tx-stream tls) hdr)
       (write-value 'alert (tx-stream tls) alert))
)))

(defun tls-close (tls)
  (send-alert tls +ALERT-WARNING+ +CLOSE-NOTIFY+))

(defun encrypted-p (tls)
  (eql (state tls) :NEGOTIATED))
