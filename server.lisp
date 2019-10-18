(in-package :tls)

(defvar *mode*)
(defvar *acceptor*)
(defvar *reader*)
(defvar *writer*)
(defvar *alerter*)
(defvar *disconnector*)
(defvar *cert-path*)
(defvar *key-path*)

(defmethod handle-key ((s socket:socket))
  (socket::socket-fd s))

(defun start-server
    (cert-path key-path port accept-fn read-fn write-fn alert-fn disconnect-fn)
  (let ((dispatcher (make-dispatcher))
	(*connections* (make-hash-table))
	(*version* +TLS-1.3+))
    (let ((*acceptor* accept-fn)
	  (*reader* read-fn)
	  (*writer* write-fn)
	  (*alerter* alert-fn)
	  (*disconnector* disconnect-fn)
	  (*cert-path* cert-path)
	  (*key-path* key-path))
      (with-dispatcher (dispatcher)
	(let ((srv-socket (make-tcp-listen-socket port)))
	  (set-non-blocking srv-socket)
	  (on-read srv-socket #'accept-tls-connection)
	  (loop
	     do
	       (let ((events (wait-for-events)))
		 (dispatch-events events))))))))

(defun make-new-context (new-socket)
  (make-server-tls-connection
   new-socket
   :CLIENT-HELLO
   nil
   *acceptor*
   *reader*
   *writer*
   *alerter*
   *disconnector*))

(defun accept-tls-connection (ctx event)
  (declare (ignore event))
  (let ((socket (context-handle ctx)))
    (tagbody
     again
       (handler-case
	   (let ((new-socket (socket:accept socket)))
	     (let ((newctx (make-new-context new-socket)))
	       (when (accept-fn newctx)
		 (let ((newdata (funcall (accept-fn newctx) newctx)))
		   (setf (data newctx) newdata)))

	       (set-non-blocking new-socket)
	       (on-read new-socket #'tls-rx newctx)
	       (on-disconnect new-socket #'tls-disconnect))
	     (go again))
	 (operation-interrupted () (go again))
	 (operation-would-block ())))))

(defun rx-into-buffer (sd buf nbytes)
  (let ((nrecvd 0)
	(locs (alien-ring::ring-buffer-write-locations buf nbytes))
	(occupied (alien-ring::ring-buffer-size buf))
	(free (alien-ring::ring-buffer-available buf))
	(capacity (alien-ring::ring-buffer-capacity buf)))
    (loop for loc in locs
       do
	 (let* ((bufaddr (sb-sys:sap+ (alien-ring::ring-buffer-ptr buf) (car loc)))
		(ret (socket::receive sd (list bufaddr) (list (cdr loc)))))
	   (alien-ring::ring-buffer-advance-wr buf ret)
	   (incf nrecvd ret)
	   (decf nbytes ret)))
    nrecvd))

(defun tx-from-buffer (sd buf n)
  (let ((nsent 0))
    (loop for loc in (alien-ring::ring-buffer-read-locations buf n)
       do
	 (let* ((xfer-size (cdr loc))
		(bufaddr (sb-sys:sap+ (alien-ring::ring-buffer-ptr buf) (car loc)))
		(ret (socket::send sd bufaddr xfer-size)))
	   (alien-ring::ring-buffer-advance-rd buf ret)
	   (incf nsent ret)))
    nsent))

(defun tls-tx (ctx event)
  (declare (ignorable ctx event))
  (let* ((sd (context-handle ctx))
	 (tls (context-data ctx)))
    (with-slots (tx) tls
      ;; call the tx handler ? see if the application has anything to send?
      (loop
	 while (or (plusp (alien-ring:stream-size tx))
		   (and (plusp (stream-space-available tx))
			(plusp (queue-count (tx-queue tls)))))
	 do
	   (handler-case
	       (let* ((xfer-requested (stream-size tx))
		      (txbuf (stream-buffer tx))
		      (nsent (tx-from-buffer sd txbuf xfer-requested)))
		 (when (/= nsent xfer-requested)
		   (format t "WARNING: TODO implement?~%"))

		 (when (plusp (queue-count (tx-queue tls)))
		   (let ((min-xfer (+ 1 5 16))
			 (free-space (alien-ring:ring-buffer-available (stream-buffer tx))))
		     (when (> free-space min-xfer)
		       (let ((elem (queue-peek (tx-queue tls))))
			 (let ((remaining (- (length (cdr elem)) (car elem))))
			   (let ((xfer-size (min (- free-space min-xfer) remaining)))
			     (let ((record (make-instance 'tls-record
							  :size (+ 16 1 xfer-size)
							  :content-type +RECORD-APPLICATION-DATA+)))
			       (write-value 'tls-record (tx-stream tls) record)
			       (let ((next-xfer-seq (subseq (cdr elem) (car elem) (+ (car elem) xfer-size))))
				 (multiple-value-bind (ciphertext authtag)
				     (encrypt-data tls next-xfer-seq)
				   (write-sequence ciphertext (tx-stream tls))
				   (write-sequence authtag (tx-stream tls)))))

			     (incf (car elem) xfer-size)
			     (when (= (car elem) (length (cdr elem)))
			       (dequeue (tx-queue tls))))))))))

	     (socket:socket-write-error ()
	       (format t "socket write error~%")
	       (rem-handle (context-handle ctx))
	       (return-from tls-tx))

	     (operation-would-block ()
	       (format t "operation would block~%")
	       (return-from tls-tx))

	     (operation-interrupted ()
	       (format t "operation interrupted~%")
	       (return-from tls-tx))))

      (when (alien-ring:ring-buffer-empty-p (stream-buffer tx))
	;; no more data to send. disable write notifications
	(del-write sd)))))

(defun send-close-notify (ctx evt)
  (let* ((sd (context-handle ctx))
	 (tls (context-data ctx)))
    (send-alert tls +ALERT-WARNING+ +CLOSE-NOTIFY+)
    (tls-tx ctx evt)
    (rem-handle sd)
    (disconnect sd)))

(defun send-protocol-alert (ctx evt)
  (let* ((sd (context-handle ctx))
	 (tls (context-data ctx)))
    (send-alert tls +ALERT-FATAL+ +PROTOCOL-VERSION+)
    (tls-tx ctx evt)
    (rem-handle sd)
    (disconnect sd)))

(defun send-insufficient-security-alert (ctx evt)
  (let* ((sd (context-handle ctx))
	 (tls (context-data ctx)))
    (send-alert tls +ALERT-FATAL+ +INSUFFICIENT-SECURITY+)
    (tls-tx ctx evt)
    (rem-handle sd)
    (disconnect sd)))

(defun tls-disconnect (ctx event)
  "Top level handler for disconnect events."
  (declare (ignore event))
  (let* ((sd (context-handle ctx))
	 (nbytes (socket:get-rxbytes sd))
	 (*mode* :SERVER))
    (let ((tls (context-data ctx)))
      (rem-handle sd)
      (format t "disconnecting in tls-disconnect~%")
      (disconnect sd))))

(defun tls-rx (ctx event)
  "Top level read notification handler to plug into the reactor."
  (declare (ignore event))
  (let* ((sd (context-handle ctx))
	 (nbytes (socket:get-rxbytes sd))
	 (*mode* :SERVER)
	 (tls (context-data ctx)))
    (with-slots (rx rxbuf pending records) tls
      (handler-case
	  (progn
	    ;; read pending bytes from the socket into the tls buffer
	    (rx-into-buffer sd (stream-buffer rx) nbytes)

	    (when pending
	      (let ((hdr pending))
		(cond
		  ((>= (stream-size rx) (size hdr))
		   (setf records (append records (list hdr)))
		   (transfer-rx-record tls hdr)
		   (setf pending nil))
		  (t (return-from tls-rx)))))

	    ;; read the record header (5 bytes) from the rx queue
	    ;; and push it to the records list.
	    (loop
	       while (not pending)
	       while (>= (stream-size rx) 5)
	       do
		 (let ((hdr (read-value 'tls-record rx)))
		   ;; sanity check the record header and only allow
		   ;; TLS-1.2 because the field is obsoleted. anything
		   ;; less than TLS 1.2 is dropped
		   (unless (and (valid-content-p (content-type hdr))
				(valid-version-p (protocol-version hdr)))

		     ;; stop reading from this socket
		     (del-read (socket tls))
		     ;; on next write, we send the protocol alert
		     (on-write sd #'send-protocol-alert tls)
		     (return-from tls-rx))

		   (setf (tls-records tls)
			 (append (tls-records tls) (list hdr)))

		   (cond
		     ;; check if the ring buffer has enough data for a
		     ;; complete record and if so, process it immediately
		     ((>= (stream-size rx) (size hdr))
		      ;; here, we need to read the packet bytes and transfer
		      ;; them into another buffer that is aggregating
		      ;; fragments into complete higher level packets.  we
		      ;; can't read the packet yet because it could have
		      ;; been fragmented across many records

		      ;; transfer the record bytes from the RX stream into
		      ;; TLS-RX de-encapsulating from the record layer
		      (let ((*mode* :CLIENT))
			(transfer-rx-record tls hdr)))

		     ;; if not enough data present, we need to wait for
		     ;; another read event to continue filling the record
		     ((< (stream-size rx) (size hdr))
		      (setf pending hdr)
		      (loop-finish)))))

	    ;; process de-encapsulated records until we reach the
	    ;; end of the list or an incomplete record
	    (loop for hdr in records
	       do (server-process-record tls)
		 (pop records)))

	(alert-arrived (a)
	  (with-slots (alert) a
	    (format t "~a~%" a)
	    (on-write (socket tls) #'send-close-notify)))

	(socket-eof ()
	  (format t "closing connection on socket ~a~%" (socket tls))
	  (rem-handle (socket tls))
	  (disconnect (socket tls)))

	(no-common-cipher ()
	  (del-read (socket tls))
	  (on-write (socket tls) #'send-insufficient-security-alert))))))

(defun transfer-rx-record (tls hdr)
  (with-slots (rx tlsrx) tls
    (assert (>= (alien-ring::ring-buffer-available (stream-buffer tlsrx))
		(size hdr)))
    ;; copy the bytes without deserializing/serializing
    (let ((tmpbuf (make-array (size hdr) :element-type '(unsigned-byte 8))))
      (read-sequence tmpbuf rx)
      (write-sequence tmpbuf tlsrx))))

(defun transfer-tx-record (tls msg)
  (with-slots (tx tlstx) tls
    (let ((rec (make-instance 'tls-record
			      :size (+ 4 (size msg))
			      :content-type +record-handshake+)))
      (write-value (type-of rec) tx rec)
      (write-value (type-of msg) tx msg))))

(defun record-completep (tls)
  (let ((hd (first (tls-records tls))))
    (>= (stream-size (tls-rx-stream tls))
	(size hd))))

(defun make-finished-key (secret &optional (hash :sha384))
  (hkdf-expand-label
   secret "finished" "" (hash-len hash) :hash hash))

(defun hmac (key ctx &optional (hash :sha384))
  (ironclad:produce-mac
   (ironclad:update-hmac
    (ironclad:make-hmac key hash)
    ctx)))

(defun get-out-nonce! (tls)
  (let ((nonce (nonce-out tls)))
    (incf (nonce-out tls))
    nonce))

(defun get-in-nonce! (tls)
  (let ((nonce (nonce-in tls)))
    (incf (nonce-in tls))
    nonce))

(defun reset-nonces! (tls)
  (setf (nonce-in tls) 0
	(nonce-out tls) 0))

(defun server-process-record (tls)
  (with-slots (tlsrx state records) tls
    (let ((content-type (get-record-content-type (first records))))
      (case state
	(:CLIENT-HELLO
	 ;; peek at the sequence and compute the hash
	 (let ((client-hello (let ((*mode* :CLIENT))
			       (read-value content-type tlsrx))))

	   (when (/= (get-version client-hello) +TLS-1.3+)
	     (on-write (socket tls) #'send-protocol-alert tls)
	     (del-read (socket tls))
	     (return-from server-process-record))

	   ;; process the record here...
	   (setf (state tls) :SERVER-HELLO)
	   (send-server-hello tls client-hello)
	   (send-change-cipher-spec tls)
	   (send-server-certificate tls)))


	(:SERVER-HELLO
	 ;; watch out for client cipher change spec here...
	 (cond
	   ((eq content-type 'change-cipher-spec)
	    (format t "cipher spec arrived with value of ~a~%"
		    (read-value 'change-cipher-spec tlsrx))))
	 (setf (state tls) :SERVER-FINISHED))

	(:SERVER-FINISHED
	 (let ((record (decrypt-record tls (first (tls-records tls)))))
	   (format t "record type=~a~%" (type-of record))
	   (etypecase record
	     (alert
	      (format t "~a~%" record))

	     (change-cipher-spec
	      (format t "peer running in compatibility mode. ignoring cipher change packet~%"))

	     (finished
	      (let* ((key (make-finished-key (peer-handshake-secret tls) :sha384))
		     (hash (ironclad:produce-digest (digest-stream tls)))
		     (data (hmac key hash :sha384)))

		(if (array= data (data record))
		    (progn
		      (reset-nonces! tls)
		      (setf (state tls) :NEGOTIATED))
		    (error "todo: send an alert and abort the connection")))))))

	(:NEGOTIATED
	 (decrypt-record tls (first (tls-records tls)))

	 (when (plusp (stream-size (rx-data-stream tls)))
	   (when (read-fn tls)
	     (funcall (read-fn tls)
		      (data tls)
		      (stream-size (rx-data-stream tls))))))))))

(defun array= (a b)
  (unless (= (length a) (length b))
    (return-from array= nil))
  (loop
     for elem-a across a
     for elem-b across b
     when (/= elem-a elem-b) do (return-from array= nil)
     while (= elem-a elem-b))
  t)

(defun array/= (a b)
  (not (array= a b)))

(defun auth-tag= (tag-a tag-b)
  (array= tag-a tag-b))

(defun auth-tag/= (tag-a tag-b)
  (not (auth-tag= tag-a tag-b)))

(defun pick-common-cipher (ciphers)
  (first
   (intersection ciphers (list +TLS-AES-256-GCM-SHA384+))))

(defun compute-dh-shared-secret (tls)
  (declare (optimize (debug 3) (speed 0)))
  (let ((mine (privkey tls))
	(theirs (peer-key-exchange-key tls)))
    (diffie-hellman theirs mine)))

(defun send-change-cipher-spec (tls)
  (let ((rec (make-instance 'tls-record
			    :content-type +RECORD-CHANGE-CIPHER-SPEC+
			    :size 1))
	(msg (make-instance 'change-cipher-spec)))
    (write-value (type-of rec) (tx-stream tls) rec)
    (write-value (type-of msg) (tx-stream tls) msg)))

(defun send-server-hello (tls client-hello)
  (with-slots (txbuf state current-record pubkey seckey) tls
    (let ((exts '())
	  (supported-group 0)
	  (key-share-group 0)
	  (cipher nil)
	  (key (make-curve25519-keypair)))
      ;; pick a common cipher
      (setf cipher (pick-common-cipher (ciphers client-hello))
	    pubkey key
	    seckey key)
      (unless cipher
	(error (make-condition 'no-common-cipher)))

      ;; iterate over the extensions and process relevant information
      (loop for ext in (extensions client-hello)
	 do
	   (typecase ext
	     (supported-groups
	      (setf supported-group
		    (first
		     (intersection
		      (named-groups ext)
		      (list +x25519+))))

	      (unless supported-group
		(error 'no-common-group-found))

	      (push
	       (make-server-keyshare
		supported-group
		(public-key-bytes (pubkey tls))) exts))

	     (client-hello-key-share
	      (let ((keyshare (find +x25519+ (key-shares ext) :key #'named-group :test #'=)))
		(setf (peer-key-exchange-key tls)
		      (make-curve25519-public-key (key-exchange keyshare))
		      key-share-group (named-group keyshare))

		;; diffie-hellman key exchange
		(setf (shared-secret tls)
		      (compute-dh-shared-secret tls))))
	     (t
	      (format t "~a~%" ext))))

      (unless (= supported-group key-share-group)
	(error 'key-share-and-supported-groups-dont-match))
      (push (make-server-supported-versions) exts)

      (let ((server-hello (make-server-hello cipher (session-id client-hello) exts)))
	;; calculate digest of client hello and server hello
	(update-digest tls client-hello)
	(update-digest tls server-hello)

	(multiple-value-bind (hs-secret ss skey siv cs ckey civ)
	    (handshake-key-schedule
	     (shared-secret tls) (ironclad:produce-digest (digest-stream tls))
	     :hash :sha384 :cipher :aes256)
	  (setf (handshake-secret tls) hs-secret
		(my-handshake-secret tls) ss
		(my-handshake-key tls) skey
		(my-handshake-iv tls) siv
		(peer-handshake-secret tls) cs
		(peer-handshake-key tls) ckey
		(peer-handshake-iv tls) civ))

	(transfer-tx-record tls server-hello)
	(on-write (socket tls) #'tls-tx)))))

(defun scan-for-content-type (plaintext)
  (loop for i downfrom (1- (length plaintext)) to 0
     while (zerop (aref plaintext i))
     finally (return i)))

(defun xor-initialization-vector (iv counter)
  (let ((ctr-iv (copy-seq iv)))
    (loop
       for bit downfrom (- 64 8) downto 0 by 8
       for i from (- (length iv) 8) to (length iv) by 1
       do
	 (let ((byte (aref iv i))
	       (ctrbyte (ldb (byte 8 bit) counter)))
	   (setf (aref ctr-iv i) (logxor byte ctrbyte))))
    ctr-iv))

(defun make-aead-aes256-gcm (key orig-iv counter)
  (let ((iv (xor-initialization-vector orig-iv counter)))
    (ironclad:make-authenticated-encryption-mode
     :gcm :cipher-name :aes :key key
     :initialization-vector iv)))

(defun sign-certificate-verify (tls)
  (ironclad:sign-message
   (load-private-key-der *key-path*)
   (alien-ring::with-output-to-byte-sequence (out (+ 64 33 1 48))
     (let ((space-vector
	    (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x20))
	   (label (ironclad:ascii-string-to-byte-array
		   "TLS 1.3, server CertificateVerify")))
       (write-sequence space-vector out)
       (loop for elem across label do (write-byte elem out))
       (write-byte 0 out)
       (write-sequence (ironclad:produce-digest (digest-stream tls)) out)))
   :pss :sha256))

(defun make-certificate-verify (signature)
  (make-instance
   'certificate-verify
   :handshake-type +certificate-verify+
   :size (+ 2 2 (length signature))
   :signature signature
   :signature-scheme +rsa-pss-rsae-sha256+))

(defun make-server-finished (tls)
  (let* ((finished-key (make-finished-key (my-handshake-secret tls) :sha384))
	 (finished-hash (ironclad:produce-digest (digest-stream tls)))
	 (finished-data (ironclad:produce-mac
			 (ironclad:update-hmac
			  (ironclad:make-hmac finished-key :sha384)
			  finished-hash))))
    (make-instance 'finished :size (hash-len :sha384)
		   :handshake-type +FINISHED+
		   :data finished-data)))

(defun send-server-certificate (tls)
  (let* ((x509cert (read-x509-certificate *cert-path* :der))
	 (exts (make-encrypted-extensions '()))
	 (certmsg (make-server-certificate (bytes x509cert))))

    ;; update handshake digest
    (update-digest tls exts)
    (update-digest tls certmsg)

    (let ((signature (sign-certificate-verify tls)))
      (let ((cert-verify (make-certificate-verify signature)))
	;; update the handshake digest with the certificate verify message
	(update-digest tls cert-verify)

	(let* ((finished (make-server-finished tls)))
	  (update-digest tls finished)

	  (let* ((aead (make-aead-aes256-gcm (my-handshake-key tls)
					     (my-handshake-iv tls)
					     (get-out-nonce! tls)))
		 (ciphertext (encrypt-messages aead
			      (list exts certmsg cert-verify finished)
			      +RECORD-HANDSHAKE+))
		 (rec (make-instance 'tls-record :size (+ 16 (length ciphertext))
				     :content-type +RECORD-APPLICATION-DATA+)))
	    (write-value 'tls-record (tx-stream tls) rec)

	    (write-sequence ciphertext (tx-stream tls))
	    (write-sequence (ironclad:produce-tag aead) (tx-stream tls)))

	  ;; TODO: this placement is temporary until next refactor
	  (multiple-value-bind (ss sk siv cs ck civ)
	      (application-key-schedule
	       (handshake-secret tls)
	       (ironclad:produce-digest (digest-stream tls)))
	    (setf (my-app-secret tls) ss
		  (my-app-key tls) sk
		  (my-app-iv tls) siv
		  (peer-app-secret tls) cs
		  (peer-app-key tls) ck
		  (peer-app-iv tls) civ)))))))


(defun decryption-key (tls)
  (case (state tls)
    (:SERVER-FINISHED (peer-handshake-key tls))
    (:NEGOTIATED (peer-app-key tls))))

(defun decryption-iv (tls)
  (case (state tls)
    (:SERVER-FINISHED (peer-handshake-iv tls))
    (:NEGOTIATED (peer-app-iv tls))))

(defgeneric decrypt-record (tls hdr))

(defmethod decrypt-record ((tls tls13-connection) hdr)
  (let ((ciphertext (make-array (size hdr) :element-type '(unsigned-byte 8)))
	(assocdata
	 (ironclad:hex-string-to-byte-array
	  (format nil "170303~4,'0x" (size hdr)))))
    (read-sequence ciphertext (tls-rx-stream tls))
    (let* ((key (decryption-key tls))
	   (iv (decryption-iv tls))
	   (nonce (get-in-nonce! tls))
	   (aead (make-aead-aes256-gcm key iv nonce)))

      (let* ((plaintext (make-array (- (size hdr) 16) :element-type '(unsigned-byte 8))))
	(ironclad:process-associated-data aead assocdata)
	(multiple-value-bind (consumed produced)
	    (ironclad:decrypt
	     aead ciphertext plaintext
	     :handle-final-block t
	     :ciphertext-end (- (size hdr) 16))
	  (declare (ignore consumed produced)))

	(let* ((content-type-pos (scan-for-content-type plaintext))
	       (type (tls-content->class (aref plaintext content-type-pos))))
	  (ecase type
	    (handshake
	     (with-input-from-sequence (in plaintext)
	       (read-value type in)))

	    (alert
	     (with-input-from-sequence (in plaintext)
	       (error 'alert-arrived :alert (read-value type in))))

	    (application-data
	     (write-sequence
	      plaintext (rx-data-stream tls) :start 0 :end (1- (length plaintext))))))))))

(defun gen-aead-data (size)
  (with-output-to-byte-sequence (buf 5)
    (let ((data (make-aead-data (+ 16 size))))
      (write-value (type-of data) buf data))))

(defun encrypt-messages (gcm msgs content-type)
  (let* ((total-size (+ 1 (reduce #'+ (mapcar #'tls-size msgs))))
	 (aead-data (gen-aead-data total-size)))
    (let ((plaintext
	   (alien-ring::with-output-to-byte-sequence (out total-size)
	     (loop for msg in msgs
		do (write-value (type-of msg) out msg))
	     (write-value 'u8 out content-type))))
      (ironclad:encrypt-message gcm plaintext :associated-data aead-data))))

(defun update-digest (tls message)
  (format t "handshake digest: before update: ~a~%"
	  (ironclad:byte-array-to-hex-string
	   (ironclad:produce-digest
	    (digest-stream tls))))

  (format t "updating handshake digest with message type ~a:~%~a~%"
	  (type-of message) message)

  (write-value (type-of message) (digest-stream tls) message)

  (format t "handshake digest: after update: ~a~%"
	  (ironclad:byte-array-to-hex-string
	   (ironclad:produce-digest
	    (digest-stream tls)))))
