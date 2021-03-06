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
   (pending :initform nil :accessor tls-pending)
   (state :initform nil :initarg :state :accessor state)
   (pubkey :initform nil :accessor pubkey)
   (seckey :initform nil :accessor privkey)
   (peer-key-exchange-key :initform nil :accessor peer-key-exchange-key)

   (peername :initform nil :accessor peername :initarg :peername)

   (cipher :initform nil :accessor cipher)
   (hashalgo :initform nil :accessor hash-scheme)
   (sigalgo :initform nil :accessor signature-scheme)
   (elliptic-curve :initform nil :accessor tls-ec)

   (key-exchange-mode :accessor key-exchange-mode)

   (handshake-stream :initform
		     (ironclad:make-digesting-stream :sha384)
		     :accessor digest-stream)
   (record-hash :initform nil)
   (shared-secret :initform nil :accessor shared-secret)

   (mode :accessor tls-mode)

   (nonce-in :initform 0 :accessor nonce-in)
   (nonce-out :initform 0 :accessor nonce-out)

   (socket :accessor socket :initform -1 :initarg :socket)
   (certificate :accessor certificate)

   ;; callbacks
   (accept-fn :initform nil :accessor accept-fn :initarg :accept-fn)
   (connect-fn :initform nil :accessor connect-fn :initarg :connect-fn)
   (read-fn :initform nil :accessor read-fn :initarg :read-fn)
   (write-fn :initform nil :accessor write-fn :initarg :write-fn)
   (alert-fn :initform nil :accessor alert-fn :initarg :alert-fn)
   (disconnect-fn :initform nil :accessor disconnect-fn :initarg :disconnect-fn)

   ;; overflow transmit queue of 512 slots
   (tx-queue :initform (make-queue 512) :reader tx-queue)

   ;; user data
   (data :accessor data :initarg :data)
   (version :accessor tls-version :initform nil :initarg :version)

   (client-random :accessor client-random)
   (server-random :accessor server-random)))

#+off
(defmethod print-object ((obj tls-connection) stream)
  (with-slots (state pubkey seckey cipher hashalgo sigalgo) obj
    (format stream "state=~a, pubkey=~a, seckey=~a, cipher=~a, hashalgo=~a, sigalgo=~a"
	    state pubkey seckey cipher hashalgo sigalgo)))

(defclass tls12-connection (tls-connection)
  ((protocol :initform +TLS-1.2+ :accessor protocol)
   (my-mac-key :initform nil :accessor my-mac-key)
   (my-key :initform nil :accessor my-key)
   (my-iv :initform nil :accessor my-iv)
   (peer-mac-key :initform nil :accessor peer-mac-key)
   (peer-key :initform nil :accessor peer-key)
   (peer-iv :initform nil :accessor peer-iv)))

(defclass tls13-connection (tls-connection)
  ((protocol :initform +TLS-1.3+ :accessor protocol)
   (handshake-secret :initform nil :accessor handshake-secret)

   (my-secret :initform nil :accessor my-handshake-secret)
   (my-hs-key :accessor my-handshake-key)
   (my-hs-iv :accessor my-handshake-iv)

   (peer-hs-secret :accessor peer-handshake-secret)
   (peer-hs-key :accessor peer-handshake-key)
   (peer-hs-iv :accessor peer-handshake-iv)

   (master-secret :initform nil :accessor master-secret)

   (my-app-secret :accessor my-app-secret)
   (my-app-key :accessor my-app-key)
   (my-app-iv :accessor my-app-iv)

   (peer-app-secret :accessor peer-app-secret)
   (peer-app-key :accessor peer-app-key)
   (peer-app-iv :accessor peer-app-iv)))

(defun make-tls-connection
    (host socket state data connect-fn read-fn
     write-fn alert-fn disconnect-fn)
  (make-instance 'tls-connection
		 :peername host
		 :socket socket
		 :state state
		 :data data
		 :connect-fn connect-fn
		 :read-fn read-fn
		 :write-fn write-fn
		 :alert-fn alert-fn
		 :disconnect-fn disconnect-fn))

(defun make-server-tls-connection
    (socket state data accept-fn read-fn
     write-fn alert-fn disconnect-fn)
  (make-instance 'tls13-connection
		 :socket socket
		 :state state
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

(defmethod tls-write ((tls tls13-connection) (seq array) &optional (content-type +RECORD-APPLICATION-DATA+))
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

(defmethod tls-write ((tls tls12-connection) data &optional content-type)
  (declare (ignore content-type))
  (let* ((len (length data))
	 (key (my-key tls))
	 (explicit-iv (ironclad:random-data 8))
	 (salt-iv (my-iv tls))
	 (plaintext nil)
	 (combined-iv (concatenate '(vector (unsigned-byte 8)) salt-iv explicit-iv)))
    (etypecase data
      (string
       (setf plaintext
	     (make-array (length data)
			 :element-type '(unsigned-byte 8)
			 :initial-contents (map '(vector (unsigned-byte 8)) #'char-code data))))
      (vector
       (setf plaintext data)))

    (let* ((nonce (get-out-nonce! tls))
	   (aead (make-aead-aes256-gcm key combined-iv 0))
	   (aead-data (tls12-make-aead-data nonce +RECORD-APPLICATION-DATA+ +TLS-1.2+ len))
	   (ciphertext (ironclad:encrypt-message aead plaintext :associated-data aead-data))
	   (rec (make-instance 'tls-record
			       :size (+ 8 len 16)
			       :content-type +RECORD-APPLICATION-DATA+)))
      (write-value 'tls-record (tx-stream tls) rec)
      (write-value 'raw-bytes (tx-stream tls) explicit-iv :size (length explicit-iv))
      (write-sequence ciphertext (tx-stream tls))
      (write-sequence (ironclad:produce-tag aead) (tx-stream tls))))
  (on-write (socket tls) #'tls-tx))

(defun alert->bytes (alert)
  (with-output-to-byte-sequence (out 2)
    (write-value 'alert out alert)))

(defun send-alert (tls level desc)
  (let ((alert (make-instance 'alert :level level :description desc))
	(hdr (make-instance 'tls-record :content-type +RECORD-ALERT+ :size 2)))
    (cond
      ((encrypted-p tls)
       (let ((record (make-instance 'tls-record :size (+ 16 1 2) :content-type +RECORD-APPLICATION-DATA+)))
	(write-value 'tls-record (tx-stream tls) record)
	(multiple-value-bind (ciphertext authtag)
	    (encrypt-data tls (alert->bytes alert) +RECORD-ALERT+)
	  (write-sequence ciphertext (tx-stream tls))
	  (write-sequence authtag (tx-stream tls)))))
      (t
       (write-value 'tls-record (tx-stream tls) hdr)
       (write-value 'alert (tx-stream tls) alert)))))

(defun tls-close (tls)
  (send-alert tls +ALERT-WARNING+ +CLOSE-NOTIFY+))

(defun encrypted-p (tls)
  (eql (state tls) :NEGOTIATED))
