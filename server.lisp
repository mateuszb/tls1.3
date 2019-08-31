(in-package :tls)

(defvar *mode*)

(defun start-server (port)
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
    (format t "received ~a bytes~%" nrecvd)
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
    (with-slots (tx) tls
      (loop
	 while (plusp (alien-ring:ring-buffer-size (stream-buffer tx)))
	 do
	   (handler-case
	       (tx-from-buffer
		sd (stream-buffer tx)
		(alien-ring:ring-buffer-size (stream-buffer tx)))
	     (operation-would-block ()
	       (loop-finish))

	     (operation-interrupted ())))

      (when (alien-ring:ring-buffer-empty-p (stream-buffer tx))
	;; no more data to send. disable write notifications
	(del-write sd)))))

(defun tls-rx (ctx event)
  "Top level read notification handler to plug into the reactor."
  (declare (ignore event))
  (let* ((sd (context-socket ctx))
	 (nbytes (socket:get-rxbytes sd))
	 (*mode* :SERVER))
    (unless (context-data ctx)
      (setf (context-data ctx) (make-tls-connection sd :CLIENT-HELLO)))

    (let ((tls (context-data ctx)))
      (with-slots (rx rxbuf) tls
	;; read pending bytes from the socket into the tls buffer
	(rx-into-buffer sd (stream-buffer rx) nbytes)

	;; read the record header (5 bytes) from the rx queue
	;; and push it to the records list.
	(loop
	   while (>= (alien-ring::ring-buffer-size (stream-buffer rx)) 5)
	   do
	     (let ((hdr (read-value 'tls-record rx)))
	       (format t "records=~a~%" (tls-records tls))
	       (if (tls-records tls)
		   (nconc (tls-records tls) (list hdr))
		   (setf (tls-records tls) (list hdr)))
	       (format t "after nconc records=~a~%" (tls-records tls))
	       (format t "tls record len = ~a~%" (size hdr))
	       (cond
		 ;; check if the ring buffer has enough data for a
		 ;; complete record and if so, process it immediately
		 ((>= (alien-ring::ring-buffer-size (stream-buffer rx))
		      (size hdr))

		  ;; here, we need to read the packet bytes and transfer
		  ;; them into another buffer that is aggregating
		  ;; fragments into complete higher level packets.  we
		  ;; can't read the packet yet because it could have
		  ;; been fragmented across many records

		  ;; transfer the record bytes between buffers
		  (transfer-rx-record tls hdr)
		  (format t "processing list of ~a records~%" (tls-records tls))
		  (loop
		     while (tls-records tls)
		     while (record-completep tls)
		     do
		       (format t "first record = ~a~%" (first (tls-records tls)))
		       (process-record tls)
		       (let ((records (tls-records tls)))
			 (cond
			   ((null (rest records)) (setf (tls-records tls) nil))
			   (t
			    (rplaca records (cadr records))
			    (rplacd records (cddr records))
			    (setf (tls-records tls) records))))
		       (format t "records is now ~a~%" (tls-records tls))))

		 ;; if not enough data present, we need to wait for
		 ;; another read event so we do nothing
		 ((< (alien-ring::ring-buffer-size (stream-buffer rx))
		     (size hdr))))))))))


(defun transfer-rx-record (tls hdr)
  (let ((*mode* :CLIENT))
    (with-slots (rx tlsrx) tls
      (assert (>= (alien-ring::ring-buffer-available (stream-buffer rx))
		  (size hdr)))
      (format t "we have enough bytes available in the ring buffer~%")
      (format t "record content type = ~a~%" (get-record-content-type hdr))

      ;; copy the bytes without deserializing/serializing
      (let ((tmpbuf (make-array (size hdr) :element-type '(unsigned-byte 8))))
	(read-sequence tmpbuf rx)
	(write-sequence tmpbuf tlsrx)))))

(defun transfer-tx-record (tls msg)
  (with-slots (tx tlstx) tls
    (let ((rec (make-instance 'tls-record
			      :size (+ 4 (size msg))
			      :content-type +record-handshake+)))
      (write-value (type-of rec) tx rec)
      (write-value (type-of msg) tx msg))))

(defun record-completep (tls)
  (let ((hd (first (tls-records tls))))
    (>= (alien-ring::ring-buffer-size (stream-buffer (tls-rx-stream tls)))
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
    (format t "new out nonce=~a~%" (nonce-out tls))
    nonce))

(defun get-in-nonce! (tls)
  (let ((nonce (nonce-in tls)))
    (incf (nonce-in tls))
    (format t "new in nonce=~a~%" (nonce-in tls))
    nonce))

(defun reset-nonces! (tls)
  (format t "resetting nonces to 0 after key change~%")
  (setf (nonce-in tls) 0
	(nonce-out tls) 0))

(defun process-record (tls)
  (with-slots (tlsrx state records) tls
    (let ((content-type (get-record-content-type (first records))))
      (format t "STATE=~a~%" state)
      (case state
	(:CLIENT-HELLO
	 (format t "processing record...~%")
	 ;; peek at the sequence and compute the hash
	 (let ((client-hello (let ((*mode* :CLIENT))
			       (read-value content-type tlsrx))))

	   ;; process the record here...
	   (setf (state tls) :SERVER-HELLO)
	   (send-server-hello tls client-hello)
	   (send-change-cipher-spec tls)
	   (send-server-certificate tls)))


	(:SERVER-HELLO
	 ;; watch out for client cipher change spec here...
	 (format t "HERE~%")
	 (cond
	   ((eq content-type 'change-cipher-spec)
	    (format t "cipher spec arrived with value of ~a~%"
		    (read-value 'change-cipher-spec tlsrx))))
	 (setf (state tls) :SERVER-FINISHED))

	(:SERVER-FINISHED
	 (format t "decrypting and processing record...~%")
	 (let ((record (decrypt-record tls (first (tls-records tls)))))
	   (etypecase record
	     (change-cipher-spec
	      (format t "peer running in compatibility mode. ignoring cipher change packet~%"))

	     (finished
	      (let* ((key (make-finished-key (client-hs-secret tls) :sha384))
		     (hash (ironclad:produce-digest (digest-stream tls)))
		     (data (hmac key hash :sha384)))

		(if (array= data (data record))
		    (progn
		      (format t "switching to using application data keys~%")
		      (reset-nonces! tls)
		      (setf (state tls) :NEGOTIATED))
		    (error "todo: send an alert and abort the connection")))))))

	(:NEGOTIATED
	 (decrypt-record tls (first (tls-records tls))))))))

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
  (let ((mine (private-key tls))
	(theirs (peer-key tls)))
    (ironclad:diffie-hellman mine theirs)))

(defun generate-keys (tls type)
  (multiple-value-bind (secret public) (ironclad:generate-key-pair type)
    (setf (private-key tls) secret
	  (public-key tls) public)))

(defun send-change-cipher-spec (tls)
  (let ((rec (make-instance 'tls-record
			    :content-type +RECORD-CHANGE-CIPHER-SPEC+
			    :size 1))
	(msg (make-instance 'change-cipher-spec)))
    (write-value (type-of rec) (tx-stream tls) rec)
    (write-value (type-of msg) (tx-stream tls) msg)
    #+off(tls::write-value (type-of msg) (digest-stream tls) msg)))

(defun send-server-hello (tls client-hello)
  (with-slots (txbuf state current-record) tls
    (let ((exts '())
	  (supported-group 0)
	  (key-share-group 0)
	  (cipher nil))
      ;; pick a common cipher
      (setf cipher (pick-common-cipher (ciphers client-hello)))
      (unless cipher
	(error 'no-common-cipher-found))

      ;; generate key pair
      (generate-keys tls :curve25519)

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
	      (push (make-server-keyshare
		     supported-group
		     (ironclad:curve25519-key-y (public-key tls)))
		    exts))
	     (client-hello-key-share
	      (let ((keyshare
		     (find +x25519+ (key-shares ext) :key #'named-group :test #'=)))
		(setf (peer-key tls)
		      (ironclad:make-public-key :curve25519 :y (key-exchange keyshare))
		      key-share-group (named-group keyshare))

		;; diffie-hellman key exchange
		(setf (shared-secret tls)
		      (compute-dh-shared-secret tls))))
	     (t
	      (format t "unsupported client extension ~a = ~a~%" (extension-type ext) ext))))

      (unless (= supported-group key-share-group)
	(error 'key-share-and-supported-groups-dont-match))
      (push (make-server-supported-versions) exts)

      (let ((server-hello (make-server-hello cipher (session-id client-hello) exts)))
	;; calculate digest of client hello and server hello
	(write-value (type-of client-hello) (digest-stream tls) client-hello)
	(write-value (type-of server-hello) (digest-stream tls) server-hello)

	(format t "handshake-digest ~a~%"
		(ironclad:byte-array-to-hex-string
		 (ironclad:produce-digest (digest-stream tls))))

	(multiple-value-bind (hs-secret ss skey siv cs ckey civ)
	    (handshake-key-schedule
	     (shared-secret tls) (ironclad:produce-digest (digest-stream tls))
	     :hash :sha384 :cipher :aes256)
	  (setf (handshake-secret tls) hs-secret
		(server-hs-secret tls) ss
		(server-hs-key tls) skey
		(server-hs-iv tls) siv
		(client-hs-secret tls) cs
		(client-hs-key tls) ckey
		(client-hs-iv tls) civ))

	(transfer-tx-record tls server-hello)
	(on-write (socket tls) #'tls-tx)
	#+off(send-server-certificate tls)))))

(defun scan-for-content-type (plaintext)
  (loop for i downfrom (1- (length plaintext)) to 0
     do
       (format t "pos = ~a~%" i)
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
    (format t "making AES256-GCM with nonce=~a~%" counter)
    (format t "original IV: ~a~%" orig-iv)
    (format t "new IV     : ~a~%" iv)
    (ironclad:make-authenticated-encryption-mode
     :gcm :cipher-name :aes :key key
     :initialization-vector iv)))

(defun send-server-certificate (tls)
  (let* ((x509cert (read-x509-certificate #p"~/ssl-dev/server.der" :der))
	 (exts (make-encrypted-extensions '()))
	 (certmsg (make-server-certificate (bytes x509cert)))
	 (tmp-aead (ironclad:make-authenticated-encryption-mode
	   :gcm :cipher-name :aes :key (server-hs-key tls)
	   :initialization-vector (server-hs-iv tls))))
    #+off
    (setf (srv-hs-aead tls)

	  (cli-hs-aead tls)
	  (ironclad:make-authenticated-encryption-mode
	   :gcm :cipher-name :aes :key (client-hs-key tls)
	   :initialization-vector (client-hs-iv tls)))

    ;; update handshake digest
    (write-value (type-of exts) (digest-stream tls) exts)
    (write-value (type-of certmsg) (digest-stream tls) certmsg)

    (let ((signature
	   (ironclad:sign-message
	    (load-private-key-der #p"~/ssl-dev/key.der")
	    (alien-ring::with-output-to-byte-sequence (out (+ 64 33 1 48))
	      (let ((space-vector
		     (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x20))
		    (label (ironclad:ascii-string-to-byte-array
			    "TLS 1.3, server CertificateVerify")))
		(write-sequence space-vector out)
		(loop for elem across label do (write-byte elem out))
		(write-byte 0 out)
		(write-sequence (ironclad:produce-digest (digest-stream tls)) out)))
	    :pss :sha256)))

      (format t "signature=~a~%" signature)
      (let ((cert-verify
	     (make-instance
	      'certificate-verify
	      :handshake-type +certificate-verify+
	      :size (+ 2 2 (length signature))
	      :signature signature
	      :signature-scheme +rsa-pss-rsae-sha256+)))
	;; update the handshake digest with the certificate verify message
	(write-value (type-of cert-verify) (digest-stream tls) cert-verify)

	(let* ((finished-key
		(hkdf-expand-label
		 (server-hs-secret tls) "finished" ""
		 (hash-len :sha384) :hash :sha384))
	       (finished-hash (ironclad:produce-digest (digest-stream tls)))
	       (finished-data (ironclad:produce-mac
			       (ironclad:update-hmac
				(ironclad:make-hmac finished-key :sha384)
				finished-hash)))
	       (finished
		(make-instance 'finished :size (hash-len :sha384)
			       :handshake-type +FINISHED+
			       :data finished-data)))

	  (write-value (type-of finished) (digest-stream tls) finished)

	  (let* ((aead (make-aead-aes256-gcm (server-hs-key tls)
					     (server-hs-iv tls)
					     (get-out-nonce! tls)))
		 (ciphertext (encrypt-messages aead
			      (list exts certmsg cert-verify finished)
			      +RECORD-HANDSHAKE+))
		 (ciphertext2 (encrypt-messages
			       tmp-aead
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
	    (setf (server-app-secret tls) ss
		  (server-app-key tls) sk
		  (server-app-iv tls) siv
		  (client-app-secret tls) cs
		  (client-app-key tls) ck
		  (client-app-iv tls) civ))

	  #+off(setf (state tls) :SERVER-FINISHED))))))

(defun decrypt-record (tls hdr)
  (let ((ciphertext (make-array (size hdr) :element-type '(unsigned-byte 8)))
	;;(authtag (make-array 16 :element-type '(unsigned-byte 8)))
	(assocdata
	 (ironclad:hex-string-to-byte-array (format nil "170303~4,'0x" (size hdr)))))
    (read-sequence ciphertext (tls-rx-stream tls))
    (format t "ciphertext: ~a~%" ciphertext)
    (let ((aead (case (state tls)
		  (:SERVER-FINISHED (make-aead-aes256-gcm (client-hs-key tls)
							  (client-hs-iv tls)
							  (get-in-nonce! tls)))
		  (:NEGOTIATED (make-aead-aes256-gcm (client-app-key tls)
						     (client-app-iv tls)
						     (get-in-nonce! tls))))))

      (let* ((plaintext (make-array (- (size hdr) 16) :element-type '(unsigned-byte 8))))
	(ironclad:process-associated-data aead assocdata)
	(multiple-value-bind (consumed produced)
	    (ironclad:decrypt
	     aead ciphertext plaintext
	     :handle-final-block t
	     :ciphertext-end (- (size hdr) 16)))

	;; presumably if no error then decryption went ok
	(let* ((content-type-pos (scan-for-content-type plaintext))
	       (type (tls-content->class (aref plaintext content-type-pos))))
	  (case (state tls)
	    (:SERVER-FINISHED
	     (flexi-streams:with-input-from-sequence
	      (in plaintext)
	      (read-value type in)))
	    (:NEGOTIATED
	     (ecase type
	       (alert
		(format t "alert arrived~%")
		(flexi-streams:with-input-from-sequence (in plaintext)
							(inspect (read-value type in))))

	       (application-data
		;; write the application data to the decrypted RX stream
		(format t "transfering data '~a' into rx buffer"
			(map 'string #'code-char (subseq plaintext 0 (1- (length plaintext)))))
		(format t "bytes: ~a~%" plaintext)
		(write-sequence plaintext (rx-data-stream tls) :start 0 :end (1- (length plaintext)))))
	     ;; TODO: signal data available for reading by calling some
	     ;; callback?
	     )))))))

(defun gen-aead-data (size)
  (alien-ring::with-output-to-byte-sequence (buf 5)
    (let ((data (make-aead-data (+ 16 size))))
      (write-value (type-of data) buf data))))

(defun encrypt-messages (gcm msgs content-type)
  (let* ((total-size (+ 1 (reduce #'+ (mapcar #'tls-size msgs))))
	 (aead-data (gen-aead-data total-size)))
    (format t "aead data = ~a~%" (ironclad:byte-array-to-hex-string aead-data))
    (format t "total calculated size is ~a~%" total-size)
    (let ((plaintext
	   (alien-ring::with-output-to-byte-sequence (out total-size)
	     (format t "msgs=~a~%" msgs)
	     (loop for msg in msgs
		do (write-value (type-of msg) out msg))
	     (write-value 'u8 out content-type))))
      (ironclad:encrypt-message gcm plaintext :associated-data aead-data))))
