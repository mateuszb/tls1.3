(defpackage :tls/test-server
  (:use :cl :tls :alien-ring :socket :reactor :reactor.dispatch))

(in-package :tls/test-server)

(defvar *connections*)

(defstruct tls-connection
  (tlsrx (make-binary-ring-stream 8192))
  (tlstx (make-binary-ring-stream 8192))
  (rx (make-binary-ring-stream 8192))
  (tx (make-binary-ring-stream 8192))
  current-record
  packets
  state
  pubkey
  seckey
  peer-pubkey
  (handshake-stream (ironclad:make-digesting-stream :sha256))
  record-hash
  shared-secret
  ssecret
  server-key
  server-iv
  csecret
  client-key
  client-iv
  mode
  aead
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
	       (tx-from-buffer sd (stream-buffer tx) (alien-ring:ring-buffer-size (stream-buffer tx)))
	     (operation-would-block ()
	       (format t "would block~%")
	       (loop-finish))

	     (operation-interrupted ())))

      (when (alien-ring:ring-buffer-empty-p (stream-buffer tx))
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
      (with-slots (rx rxbuf) tls
	;; read pending bytes from the socket into the tls buffer
	(rx-into-buffer sd (stream-buffer rx) nbytes)

	(when (tls-connection-current-record tls)
	  ;; we are in the middle of procesing of a record so let's see
	  ;; if we can finish it
	  (format t "partial record detected...~%")
	  #+off(process-record tls))

	;; deal with the rest of the remaining bytes
	(loop
	   while (>= (alien-ring::ring-buffer-size (stream-buffer rx)) 5)
	   do
	     (let ((hdr (tls::read-value 'tls::tls-record rx)))
	       (setf (tls-connection-current-record tls) hdr)
	       (format t "tls record len = ~a~%" (tls::size hdr))
	       (cond
		 ;; check if the ring buffer has enough data for a
		 ;; complete record and if so, process it immediately
		 ((>= (alien-ring::ring-buffer-size (stream-buffer rx))
		      (tls::size hdr))

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
		 ((< (alien-ring::ring-buffer-size (stream-buffer rx))
		     (tls::size hdr))))))))))

(defun transfer-rx-record (tls hdr)
  (let ((tls::*mode* :CLIENT))
    (with-slots (rx tlsrx) tls
      (assert (>= (alien-ring::ring-buffer-available (stream-buffer rx))
		  (tls::size hdr)))
      (let ((msg (tls::read-value (tls::get-record-content-type hdr) rx)))
	(tls::write-value (type-of msg) tlsrx msg)))))

(defun transfer-tx-record (tls msg)
  (with-slots (tx tlstx) tls
    (let ((rec (make-instance 'tls::tls-record
			      :size (+ 4 (tls::size msg))
			      :content-type tls::+record-handshake+)))
      (tls::write-value (type-of rec) tx rec)
      (tls::write-value (type-of msg) tx msg))))

(defun record-completep (tls)
  (with-slots (tlsrx state current-record) tls
    (when (>= (alien-ring::ring-buffer-size (stream-buffer tlsrx)) 4)
     (let ((content-type (tls::get-record-content-type current-record)))
       (format t "content type: ~a~%" content-type)
       (case content-type
	 (tls::handshake
	  (let ((type (tls::peek-value
		       'tls::unsigned-integer tlsrx 0 :bits-per-byte 8 :bytes 1))
		(size (tls::peek-value
		       'tls::unsigned-integer tlsrx 1 :bits-per-byte 8 :bytes 3)))
	    (format t "type=~a, size=~a~%" type size)
	    (cond
	      ((>= (+ 4 (alien-ring::ring-buffer-size (stream-buffer tlsrx))) size)
	       (format t "complete handshake received~%")
	       t)
	      (t nil)))))))))

(defun process-record (tls)
  (with-slots (tlsrx state current-record) tls
    (let ((content-type (tls::get-record-content-type current-record)))
      (case state
	(:CLIENT-HELLO
	 (format t "processing record...~%")
	 ;; peek at the sequence and compute the hash
	 (let ((client-hello (let ((tls::*mode* :CLIENT))
			       (tls::read-value content-type tlsrx))))

	   ;; process the record here...
	   (send-server-hello tls client-hello)))))))

(defun pick-common-cipher (ciphers)
  (first
   (intersection ciphers (list tls::+TLS-AES-256-GCM-SHA384+))))

(defun compute-dh-shared-secret (tls)
  (let ((mine (tls-connection-seckey tls))
	(theirs (tls-connection-peer-pubkey tls)))
    (ironclad:diffie-hellman mine theirs)))

(defun generate-keys (tls type)
  (multiple-value-bind (secret public) (ironclad:generate-key-pair type)
    (setf (tls-connection-seckey tls) secret
	  (tls-connection-pubkey tls) public)))

(defun send-server-hello (tls client-hello)
  (with-slots (txbuf state current-record) tls
    (let ((exts '())
	  (supported-group 0)
	  (key-share-group 0)
	  (cipher nil))
      ;; pick a common cipher
      (setf cipher (pick-common-cipher (tls::ciphers client-hello)))
      (unless cipher
	(error 'no-common-cipher-found))

      ;; generate key pair
      (generate-keys tls :curve25519)

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
	      (push (tls::make-server-keyshare
		     supported-group
		     (ironclad:curve25519-key-y (tls-connection-pubkey tls)))
		    exts))
	     (tls::client-hello-key-share
	      (let ((keyshare
		     (find tls::+x25519+ (tls::key-shares ext) :key #'tls::named-group :test #'=)))
		(setf (tls-connection-peer-pubkey tls)
		      (ironclad:make-public-key :curve25519 :y (tls::key-exchange keyshare))
		      key-share-group (tls::named-group keyshare))

		;; diffie-hellman key exchange
		(setf (tls-connection-shared-secret tls)
		      (compute-dh-shared-secret tls))))
	     (t
	      (format t "unsupported client extension ~a = ~a~%" (tls::extension-type ext) ext))))

      (unless (= supported-group key-share-group)
	(error 'key-share-and-supported-groups-dont-match))
      (push (tls::make-server-supported-versions) exts)

      (let ((hello (tls::make-server-hello cipher (tls::session-id client-hello) exts)))
	;; calculate digest of client hello and server hello
	(tls::write-value (type-of client-hello) (tls-connection-handshake-stream tls) client-hello)
	(tls::write-value (type-of hello) (tls-connection-handshake-stream tls) hello)

	(format t "handshake-digest ~a~%"
		(ironclad:byte-array-to-hex-string
		 (ironclad:produce-digest (tls-connection-handshake-stream tls))))

	(multiple-value-bind (ss skey siv cs ckey civ)
	    (tls::key-calculations :sha256 (tls-connection-shared-secret tls)
				   (ironclad:produce-digest (tls-connection-handshake-stream tls)))
	  (with-slots (ssecret server-key server-iv csecret client-key client-iv) tls
	    (setf ssecret ss
		  server-key skey
		  server-iv siv
		  csecret cs
		  client-key ckey
		  client-iv civ)))

	(transfer-tx-record tls hello)

	(send-server-certificate tls)
	(on-write (tls-connection-socket tls) #'tls-tx)))))

(defun scan-for-content-type (plaintext)
  (loop for i downfrom (1- (length plaintext)) to 0
     do
       (format t "pos = ~a~%" i)
     while (zerop (aref plaintext i))
     finally (return i)))

(defun send-server-certificate (tls)
  (let ((certmsg (tls::make-server-certificate #p"/home/mrcode/ssl-dev/server.der")))
    (let ((plaintext (flexi-streams:with-output-to-sequence (tmp)
		       (tls::write-value (type-of certmsg) tmp certmsg))))
      ;; encrypt with
      (setf (tls-connection-aead tls)
	    (ironclad:make-authenticated-encryption-mode
	     :gcm :cipher-name :aes
	     :key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
	     :initialization-vector
	     (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))))))


(defun wip ()
  (let* ((tls::*mode* :SERVER)
	 (record (ironclad:hex-string-to-byte-array "1703030475da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584ce08b0e455a350ae54d76349aa68c71ae"))
	 (tag (ironclad:hex-string-to-byte-array "e08b0e455a350ae54d76349aa68c71ae"))
	 (iv (ironclad:hex-string-to-byte-array "4c042ddc120a38d1417fc815"))
	 (key (ironclad:hex-string-to-byte-array "844780a7acad9f980fa25c114e43402a"))
	 (gcm (ironclad:make-authenticated-encryption-mode :gcm :cipher-name :aes :key key :initialization-vector iv)))
    (flexi-streams:with-input-from-sequence (s record)
      (let* ((appdata (tls::read-value 'tls::application-data s))
	     (ciphertext (subseq (tls::data appdata) 0 (- (tls::size appdata) 16)))
	     (authtag (subseq (tls::data appdata) (- (tls::size appdata) 16)))
	     (assocdata (ironclad:hex-string-to-byte-array
			 (format nil "170303~4,'0x" (tls::size appdata)))))

	(let ((plaintext
	       (ironclad:decrypt-message gcm ciphertext :associated-data assocdata)))

	  ;; so stupid... scanning backwards?
	  (let* ((content-type-pos (scan-for-content-type plaintext))
		 (rectype (tls::tls-content->class (aref plaintext content-type-pos)))
		 (plaintext (subseq plaintext 0 content-type-pos)))
	    (format t "correct tag=~a~%" (ironclad:byte-array-to-hex-string tag))
	    (format t "calculated tag=~a~%" (ironclad:byte-array-to-hex-string (ironclad:produce-tag gcm)))
	    (format t "plaintext=~a~%" plaintext)
	    (format t "ciphertext length=~a~%" (tls::size appdata))
	    (format t "plaintext length=~a~%" (length plaintext))

	    (flexi-streams:with-input-from-sequence (in plaintext)
	      (inspect (tls::read-value rectype in))
	      (inspect (tls::read-value rectype in))
	      (inspect (tls::read-value rectype in))
	      (inspect (tls::read-value rectype in)))))))))
