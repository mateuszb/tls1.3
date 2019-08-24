(defpackage :tls/test-server
  (:use :cl :tls :alien-ring :socket :reactor :reactor.dispatch))

(in-package :tls/test-server)

(defvar *connections*)

(defstruct tls-connection
  (tlsrx (make-ring-buffer 8192))
  (tlstx (make-ring-buffer 8192))
  (rxbuf (make-ring-buffer 8192))
  (txbuf (make-ring-buffer 8192))
  current-record
  packets
  state
  pubkey
  seckey
  mode
  socket)

(defun set-state (tls state)
  (setf (tls-connection-state tls) state))

(defun start (port)
  (let ((dispatcher (make-dispatcher))
	(*connections* (make-hash-table)))
    (with-dispatcher (dispatcher)
      (let ((srv-socket (make-tcp-listen-socket port)))
	(set-non-blocking srv-socket)
	(on-read srv-socket #'accept-tls-connection)
	(loop
	   do
	     (let ((events (wait-for-events)))
	       (dispatch-events events)))))))

(defun accept-tls-connection (ctx event)
  (declare (ignore event))
  (let ((socket (context-socket ctx)))
    (tagbody
     again
       (handler-case
	   (let ((new-socket (socket::accept socket)))
	     (set-non-blocking new-socket)
	     (on-read new-socket #'tls-rx)
	     (go again))
	 (operation-interrupted () (go again))
	 (operation-would-block ())))))

(defun rx-into-buffer (sd buf nbytes)
  (let ((nrecvd 0))
    (loop for loc in (alien-ring::ring-buffer-write-locations buf nbytes)
       do
	 (let* ((bufaddr (sb-sys:sap+ (alien-ring::ring-buffer-ptr buf) (car loc)))
		(ret (socket::receive sd (list bufaddr) (list nbytes))))
	   (alien-ring::ring-buffer-advance-wr buf ret)
	   (incf nrecvd ret)
	   (decf nbytes ret)))
    nrecvd))

(defun tx-from-buffer (sd buf n)
  (let ((nsent 0))
    (loop for loc in (alien-ring::ring-buffer-read-locations buf n)
       do
	 (let* ((bufaddr (sb-sys:sap+ (alien-ring::ring-buffer-ptr buf) (car loc)))
		(ret (socket::send sd bufaddr n)))
	   (alien-ring::ring-buffer-advance-rd buf ret)
	   (incf nsent ret)))
    nsent))

(defun tls-tx (ctx event)
  (declare (ignorable ctx event))
  (let* ((sd (context-socket ctx))
	 (tls (context-data ctx)))
    (with-slots (tlstx) tls
      (loop
	 while (plusp (alien-ring:ring-buffer-size tlstx))
	 do
	   (handler-case
	       (tx-from-buffer sd tlstx (alien-ring:ring-buffer-size tlstx))
	     (operation-would-block ()
	       (format t "would block~%")
	       (loop-finish))

	     (operation-interrupted ())))

      (when (alien-ring:ring-buffer-empty-p tlstx)
	(format t "no more data to send. disabling write notification~%")
	(del-write sd)))))

(defun tls-rx (ctx event)
  (declare (ignore event))
  (let* ((sd (context-socket ctx))
	 (nbytes (socket:get-rxbytes sd))
	 (tls::*mode* :SERVER))
    (unless (context-data ctx)
      (setf (context-data ctx) (make-tls-connection :socket sd))
      (set-state (context-data ctx) :CLIENT-HELLO))

    (let ((tls (context-data ctx)))
      (with-slots (tlsrx rxbuf) tls
	;; read pending bytes from the socket into the tls buffer
	(rx-into-buffer sd tlsrx nbytes)

	(when (tls-connection-current-record tls)
	  ;; we are in the middle of procesing of a record so let's see
	  ;; if we can finish it
	  (format t "partial record detected...~%")
	  #+off(process-record tls))

	;; deal with the rest of the remaining bytes
	(loop
	   while (>= (alien-ring::ring-buffer-size tlsrx) 5)
	   do
	     (let ((hdr (tls::read-value 'tls::tls-record tlsrx)))
	       (setf (tls-connection-current-record tls) hdr)
	       (format t "tls record len = ~a~%" (tls::get-record-size hdr))
	       (cond
		 ;; check if the ring buffer has enough data for a
		 ;; complete record and if so, process it immediately
		 ((>= (alien-ring::ring-buffer-size tlsrx)
		      (tls::get-record-size hdr))

		  ;; here, we need to read the packet bytes and transfer
		  ;; them into another buffer that is aggregating
		  ;; fragments into complete higher level packets.  we
		  ;; can't read the packet yet because it could have
		  ;; been fragmented across many records

		  ;; transfer the record between buffers
		  (transfer-rx-record tls hdr)
		  (loop
		     while (record-completep tls)
		     do (process-record tls)))

		 ;; if not enough data present, we need to wait for
		 ;; another read event so we do nothing
		 ((< (alien-ring::ring-buffer-size tlsrx)
		     (tls::get-record-size hdr))))))))))

(defun transfer-rx-record (tls hdr)
  (with-slots (rxbuf tlsrx) tls
    (assert (>= (alien-ring::ring-buffer-available rxbuf)
		(tls::get-record-size hdr)))
    (alien-ring::ring-buffer-write-byte-sequence
     rxbuf
     (alien-ring::ring-buffer-read-byte-sequence
      tlsrx (tls::get-record-size hdr)))))

(defun encapsulate (tls msg)
  (with-slots (txbuf tlstx) tls
    (tls::write-value (type-of msg) txbuf msg)
    (let ((rec (make-instance 'tls::tls-record
			      :len (alien-ring:ring-buffer-size txbuf)
			      :content-type tls::+record-handshake+)))
      (tls::write-value (type-of rec) tlstx rec)
      (alien-ring:ring-buffer-write-byte-sequence
       tlstx
       (alien-ring:ring-buffer-read-byte-sequence txbuf)))))

(defun transfer-tx-record (tls msg)
  (encapsulate tls msg)
  (on-write (tls-connection-socket tls) #'tls-tx))

(defun record-completep (tls)
  (with-slots (rxbuf state current-record) tls
    (when (>= (alien-ring::ring-buffer-size rxbuf) 4)
     (let ((content-type (tls::get-record-content-type current-record)))
       (format t "content type: ~a~%" content-type)
       (case content-type
	 (tls::handshake
	  (let ((type
		 (tls::peek-value
		  'tls::unsigned-integer rxbuf 0 :bits-per-byte 8 :bytes 1))
		(size
		 (tls::peek-value
		  'tls::unsigned-integer rxbuf 1 :bits-per-byte 8 :bytes 3)))
	    (format t "type=~a, size=~a~%" type size)
	    (cond
	      ((>= (+ 4 (alien-ring::ring-buffer-size rxbuf)) size)
	       (format t "complete handshake received~%")
	       t)))))))))

(defun process-record (tls)
  (with-slots (rxbuf state current-record) tls
    (let ((content-type (tls::get-record-content-type current-record)))
      (case state
	(:CLIENT-HELLO
	 (let ((client-hello (let ((tls::*mode* :CLIENT)) (tls::read-value content-type rxbuf))))
	   ;; process the record here...
	   (send-server-hello tls client-hello)))))))

(defun pick-common-cipher (ciphers)
  (first
   (intersection ciphers (list tls::+TLS-AES-256-GCM-SHA384+))))

(defun send-server-hello (tls client-hello)
  (with-slots (txbuf state current-record) tls
    (let ((exts '())
	  (supported-group nil)
	  (cipher nil))
      ;; pick a common cipher
      (setf cipher (pick-common-cipher (tls::ciphers client-hello)))
      (unless cipher
	(error 'no-common-cipher-found))
      
      ;; iterate over the extensions and process relevant information
      (loop for ext in (tls::extensions client-hello)
	 do
	   (typecase ext
	     (tls::supported-groups
	      (setf supported-group
		    (first
		     (intersection
		      (tls::named-groups ext)
		      (list tls::+x25519+))))

	      (unless supported-group
		(error 'no-common-group-found))

	      ;; generate key pair
	      (multiple-value-bind (secret public)
		  (ironclad:generate-key-pair :curve25519)
		(setf (tls-connection-seckey tls) secret
		      (tls-connection-pubkey tls) public))

	      (push (tls::make-server-keyshare
		     supported-group
		     (ironclad:curve25519-key-y (tls-connection-pubkey tls)))
		    exts))
	     (t
	      (format t "unsupported client extension ~a = ~a~%" (tls::extension-type ext) ext))))

      (push (tls::make-server-supported-versions) exts)

      (let ((hello
	     (tls::make-server-hello cipher (tls::session-id client-hello)
				     exts)))
	(transfer-tx-record tls hello)))))
