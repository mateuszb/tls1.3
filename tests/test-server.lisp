(defpackage :tls/test-server
  (:use :cl :tls :alien-ring :socket :reactor :reactor.dispatch))

(in-package :tls/test-server)

(defvar *connections*)

(defclass certificate ()
  ((path :type string :initform nil :initarg :path :accessor path)))

(defclass x509-certificate (certificate)
  ((encoding :type keyword :initform nil :initarg :encoding :accessor encoding)
   (bytes :initform nil :initarg :bytes :accessor bytes)))

(defclass tls-connection ()
  ((tlsrx :initform (make-binary-ring-stream 8192) :accessor tls-rx-stream)
   (tlstx :initform (make-binary-ring-stream 8192) :accessor tls-tx-stream)
   (rx :initform (make-binary-ring-stream 8192) :accessor rx-stream)
   (tx :initform (make-binary-ring-stream 8192) :accessor tx-stream)
   (current-record :initform nil :accessor tls-record)
   (packets :initform nil)
   (state :initform nil :accessor connection-state :initarg :state)
   (pubkey :initform nil :accessor public-key)
   (seckey :initform nil :accessor private-key)
   (peer-pubkey :initform nil :accessor peer-key)
   (handshake-stream :initform (ironclad:make-digesting-stream :sha384) :accessor digest-stream)
   (record-hash :initform nil)
   (shared-secret :initform nil :accessor shared-secret)
   (ssecret :initform nil :accessor server-secret)
   (server-hs-key :accessor server-hs-key)
   (server-hs-iv :accessor server-hs-iv)
   (csecret :accessor client-secret)
   (client-key :accessor client-hs-key)
   (client-iv :accessor client-hs-iv)
   (mode :accessor tls-mode)
   (aead :accessor aead)
   (socket :accessor socket :initform -1 :initarg :socket)
   (certificate :accessor certificate)))

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

(defun make-tls-connection (socket state)
  (make-instance 'tls-connection :socket socket :state state))

(defun tls-rx (ctx event)
  (declare (ignore event))
  (let* ((sd (context-socket ctx))
	 (nbytes (socket:get-rxbytes sd))
	 (tls::*mode* :SERVER))
    (unless (context-data ctx)
      (setf (context-data ctx) (make-tls-connection sd :CLIENT-HELLO)))

    (let ((tls (context-data ctx)))
      (with-slots (rx rxbuf) tls
	;; read pending bytes from the socket into the tls buffer
	(rx-into-buffer sd (stream-buffer rx) nbytes)

	(when (tls-record tls)
	  ;; we are in the middle of procesing of a record so let's see
	  ;; if we can finish it
	  (format t "partial record detected...~%")
	  #+off(process-record tls))

	;; deal with the rest of the remaining bytes
	(loop
	   while (>= (alien-ring::ring-buffer-size (stream-buffer rx)) 5)
	   do
	     (let ((hdr (tls::read-value 'tls::tls-record rx)))
	       (setf (tls-record tls) hdr)
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
  (let ((mine (private-key tls))
	(theirs (peer-key tls)))
    (ironclad:diffie-hellman mine theirs)))

(defun generate-keys (tls type)
  (multiple-value-bind (secret public) (ironclad:generate-key-pair type)
    (setf (private-key tls) secret
	  (public-key tls) public)))

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
		     (ironclad:curve25519-key-y (public-key tls)))
		    exts))
	     (tls::client-hello-key-share
	      (let ((keyshare
		     (find tls::+x25519+ (tls::key-shares ext) :key #'tls::named-group :test #'=)))
		(setf (peer-key tls)
		      (ironclad:make-public-key :curve25519 :y (tls::key-exchange keyshare))
		      key-share-group (tls::named-group keyshare))

		;; diffie-hellman key exchange
		(setf (shared-secret tls)
		      (compute-dh-shared-secret tls))))
	     (t
	      (format t "unsupported client extension ~a = ~a~%" (tls::extension-type ext) ext))))

      (unless (= supported-group key-share-group)
	(error 'key-share-and-supported-groups-dont-match))
      (push (tls::make-server-supported-versions) exts)

      (let ((server-hello (tls::make-server-hello cipher (tls::session-id client-hello) exts)))
	;; calculate digest of client hello and server hello
	(tls::write-value (type-of client-hello) (digest-stream tls) client-hello)
	(tls::write-value (type-of server-hello) (digest-stream tls) server-hello)

	(with-open-file (tmpfile "/tmp/msgs" :direction :output :if-exists :overwrite :element-type '(unsigned-byte 8))
	  (tls::write-value (type-of client-hello) tmpfile client-hello)
	  (tls::write-value (type-of server-hello) tmpfile server-hello))
	(format t "handshake-digest ~a~%"
		(ironclad:byte-array-to-hex-string
		 (ironclad:produce-digest (digest-stream tls))))

	(multiple-value-bind (ss skey siv cs ckey civ)
	    (tls::key-calculations :sha384 (shared-secret tls)
				   (ironclad:produce-digest (digest-stream tls)))
	  (setf (server-secret tls) ss
		(server-hs-key tls) skey
		(server-hs-iv tls) siv
		(client-secret tls) cs
		(client-hs-key tls) ckey
		(client-hs-iv tls) civ))

	(transfer-tx-record tls server-hello)
	(send-server-certificate tls)
	(on-write (socket tls) #'tls-tx)))))

(defun scan-for-content-type (plaintext)
  (loop for i downfrom (1- (length plaintext)) to 0
     do
       (format t "pos = ~a~%" i)
     while (zerop (aref plaintext i))
     finally (return i)))

(defun read-file (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((len (file-length in)))
      (let ((seq (make-array len :element-type '(unsigned-byte 8))))
	(read-sequence seq in)
	seq))))

(defun read-x509-certificate (path encoding)
  (let ((certbytes (read-file path)))
    (make-instance 'x509-certificate :encoding encoding :path path :bytes certbytes)))

(defun send-server-certificate (tls)
  (let* ((x509cert (read-x509-certificate #p"~/ssl-dev/server.der" :der))
	 (exts (tls::make-encrypted-extensions '()))
	 (certmsg (tls::make-server-certificate (bytes x509cert))))
    (setf (aead tls)
	  (ironclad:make-authenticated-encryption-mode
	   :gcm :cipher-name :aes :key (server-hs-key tls) :initialization-vector (server-hs-iv tls)))

    ;; update handshake digest
    (tls::write-value (type-of exts) (digest-stream tls) exts)
    (tls::write-value (type-of certmsg) (digest-stream tls) certmsg)

    (let ((signature
	   (ironclad:sign-message
	    (load-private-key-der #p"~/ssl-dev/key.der")
	    (alien-ring::with-output-to-byte-sequence (out (+ 64 33 1 48))
	      (let ((space-vector (make-array 64 :element-type '(unsigned-byte 8) :initial-element #x20))
		    (label (ironclad:ascii-string-to-byte-array "TLS 1.3, server CertificateVerify")))
		(write-sequence space-vector out)
		(loop for elem across label do (write-byte elem out))
		(write-byte 0 out)
		(write-sequence (ironclad:produce-digest (digest-stream tls)) out)))
	    :pss :sha256)))

      (format t "signature=~a~%" signature)
      (let ((cert-verify
	     (make-instance
	      'tls::certificate-verify
	      :handshake-type tls::+certificate-verify+
	      :size (+ 2 2 (length signature))
	      :signature signature
	      :signature-scheme tls::+rsa-pss-rsae-sha256+)))
	(let ((ciphertext
	       (encrypt-messages (aead tls) (list exts certmsg cert-verify) tls::+RECORD-HANDSHAKE+)))
	  #+off(format t "writing ciphertext = ~a~%" ciphertext)
	  (tls::write-value
	   'tls::tls-record
	   (tx-stream tls)
	   (make-instance
	    'tls::tls-record :size (+ 16 (length ciphertext))
	    :content-type tls::+RECORD-APPLICATION-DATA+))
	  (write-sequence ciphertext (tx-stream tls))
	  (format t "writing AEAD tag = ~a~%"
		  (ironclad:byte-array-to-hex-string (ironclad:produce-tag (aead tls))))
	  (write-sequence (ironclad:produce-tag (aead tls)) (tx-stream tls)))))))

(defun encrypt-messages (gcm msgs content-type)
  (let* ((total-size (+ 1 (reduce #'+ (mapcar #'tls::tls-size msgs))))
	 (aead-data
	  (alien-ring::with-output-to-byte-sequence (buf 5)
	    (let ((data (tls::make-aead-data (+ 16 total-size))))
	      (tls::write-value (type-of data) buf data)))))

    (format t "aead data = ~a~%" (ironclad:byte-array-to-hex-string aead-data))
    (format t "total calculated size is ~a~%" total-size)
    (let ((plaintext
	   (alien-ring::with-output-to-byte-sequence (out total-size)
	     (format t "msgs=~a~%" msgs)
	     (loop for msg in msgs
		do (tls::write-value (type-of msg) out msg))
	     (tls::write-value 'tls::u8 out content-type))))
      (format t "plaintext to encrypt: ~a~%" plaintext)
      (ironclad:encrypt-message
       gcm
       (make-array
	total-size
	:element-type '(unsigned-byte 8)
	:initial-contents plaintext)
       :associated-data aead-data))))

(defun wip ()
  (let* ((tls::*mode* :SERVER)
	 (record (ironclad:hex-string-to-byte-array "1703030475da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584ce08b0e455a350ae54d76349aa68c71ae"))
	 (tag (ironclad:hex-string-to-byte-array "e08b0e455a350ae54d76349aa68c71ae"))
	 (iv (ironclad:hex-string-to-byte-array "4c042ddc120a38d1417fc815"))
	 (key (ironclad:hex-string-to-byte-array "844780a7acad9f980fa25c114e43402a"))
	 (gcm (ironclad:make-authenticated-encryption-mode :gcm :cipher-name :aes :key key :initialization-vector iv))
	 (gcm2 (ironclad:make-authenticated-encryption-mode :gcm :cipher-name :aes :key key :initialization-vector iv)))
    (flexi-streams:with-input-from-sequence (s record)
      (let* ((appdata (tls::read-value 'tls::application-data s))
	     (ciphertext (subseq (tls::data appdata) 0 (- (tls::size appdata) 16)))
	     (authtag (subseq (tls::data appdata) (- (tls::size appdata) 16)))
	     (assocdata (ironclad:hex-string-to-byte-array
			 (format nil "170303~4,'0x" (tls::size appdata)))))

	(let ((plaintext
	       (ironclad:decrypt-message gcm ciphertext :associated-data assocdata)))

	  (let* ((content-type-pos (scan-for-content-type plaintext))
		 (rectype (tls::tls-content->class (aref plaintext content-type-pos)))
		 (plaintext (subseq plaintext 0 content-type-pos)))
	    (format t "correct tag=~a~%" (ironclad:byte-array-to-hex-string tag))
	    (format t "calculated tag=~a~%" (ironclad:byte-array-to-hex-string (ironclad:produce-tag gcm)))
	    (format t "plaintext=~a~%" plaintext)
	    (format t "ciphertext length=~a~%" (tls::size appdata))
	    (format t "plaintext length=~a~%" (length plaintext))

	    ;; reverse the operations by encrypting everything and
	    ;; compare the cipher text against original ciphertext
	    ;; input. they should match

	    (let ((msgs (flexi-streams:with-input-from-sequence (in plaintext)
			  (loop for i from 0 below 4 collect (tls::read-value rectype in)))))
	      (let ((ciphertext (encrypt-messages gcm2 msgs tls::+RECORD-HANDSHAKE+)))
		(format t "ciphertext=~a~%"
			(ironclad:byte-array-to-hex-string ciphertext))
		(format t "auth tag=~a~%"
			(ironclad:byte-array-to-hex-string
			 (ironclad:produce-tag gcm2)))))

	  ))))))

(defun load-private-key-der (path)
  (let ((privkey
	 (asn.1:ber-decode
	  (with-open-file (in path :element-type '(unsigned-byte 8))
	    (let ((seq (make-array (file-length in) :element-type '(unsigned-byte 8))))
	      (read-sequence seq in)
	      seq)))))
    (ironclad:make-private-key :rsa
			       :n (aref privkey 1)
			       :d (aref privkey 3))))
