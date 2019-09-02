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
   (state :initform nil :accessor connection-state :initarg :state :accessor state)
   (pubkey :initform nil :accessor public-key)
   (seckey :initform nil :accessor private-key)
   (peer-pubkey :initform nil :accessor peer-key)
   (handshake-stream :initform (ironclad:make-digesting-stream :sha384) :accessor digest-stream)
   (record-hash :initform nil)
   (shared-secret :initform nil :accessor shared-secret)
   (handshake-secret :initform nil :accessor handshake-secret)
   (ssecret :initform nil :accessor server-hs-secret)
   (server-hs-key :accessor server-hs-key)
   (server-hs-iv :accessor server-hs-iv)
   (csecret :accessor client-hs-secret)
   (client-hs-key :accessor client-hs-key)
   (client-hs-iv :accessor client-hs-iv)

   (cipher :accessor cipher)
   (hash :accessor hash)
   (key-exchange-mode :accessor key-exchange-mode)

   (master-secret :initform nil :accessor master-secret)
   (server-app-secret :accessor server-app-secret)
   (server-app-key :accessor server-app-key)
   (server-app-iv :accessor server-app-iv)

   (client-app-secret :accessor client-app-secret)
   (client-app-key :accessor client-app-key)
   (client-app-iv :accessor client-app-iv)

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
