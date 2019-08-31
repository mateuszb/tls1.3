(in-package :tls)

;; this file implements the HKDF as described in RFC5869
;; https://tools.ietf.org/html/rfc5869

(defun hash-len (hash)
  (ecase hash
    (:sha256 32)
    (:sha384 48)))

(defun key-len (cipher)
  (ecase cipher
    (:aes256 32)
    (:aes128 16)))

(defun compute-hmac (hash salt-key sequence)
  (let ((hmac (ironclad:make-hmac salt-key hash)))
    (ironclad:update-hmac hmac sequence)
    (ironclad:produce-mac hmac)))

(defun hkdf-extract (salt ikm &key (hash :sha384))
  (etypecase salt
    (string
     (format t "string case~%")
     (compute-hmac hash (ironclad:ascii-string-to-byte-array salt) ikm))
    (array
     (format t "array case. salt=~a~%" (ironclad:byte-array-to-hex-string salt))
     (compute-hmac hash salt ikm))

    (null
     (format t "null case~%") (compute-hmac hash (make-empty-array 0) ikm))))

(defun hkdf-expand (prk info len &key (hash :sha384))
  (let ((n (ceiling (/ len (hash-len hash)))))
    (subseq
     (flexi-streams:with-output-to-sequence (okm :element-type '(unsigned-byte 8))
       (labels ((make-counter-array (x)
		  (make-array 1 :element-type '(unsigned-byte 8) :initial-element x)))
	 (loop for i from 1 to n
	    with prev = (make-array 0 :element-type '(unsigned-byte 8))
	    with hmac = (ironclad:make-hmac prk hash)
	    do
	      (ironclad:update-hmac hmac prev)
	      (ironclad:update-hmac hmac info)
	      (ironclad:update-hmac hmac (make-counter-array i))
	      (setf prev (ironclad:produce-mac hmac))
	      (write-sequence prev okm))))
     0 len)))

(defun make-zero-key (hash)
  (make-empty-array (hash-len hash)))

(define-binary-class hkdf-label ()
  ((len u16)
   (label (varbytes :size-type 'u8))
   (context (varbytes :size-type 'u8))))

(defun make-empty-array (&optional (size 0))
  (make-array size :element-type '(unsigned-byte 8) :initial-element 0))

(defun get-hkdf-label-as-bytes (hash label ctx len)
  (flexi-streams:with-output-to-sequence (out :element-type '(unsigned-byte 8))
    (let ((hkdf (make-instance 'hkdf-label
			       :len len
			       :label (ironclad:ascii-string-to-byte-array
				       (format nil "tls13 ~a" label))
			       :context ctx)))
      (write-value 'hkdf-label out hkdf))))

(defun hkdf-expand-label (secret label ctx len &optional &key (hash :sha384))
  (let* ((hkdf-bytes
	  (make-array (+ 2 1 1 6 (length label) (length ctx))
		      :element-type '(unsigned-byte 8)
		      :initial-contents
		      (get-hkdf-label-as-bytes hash label ctx len))))
    (hkdf-expand secret hkdf-bytes len :hash hash)))

(defun handshake-key-schedule (shared-secret hello-hash &key (hash :sha384) (cipher :aes256))
  (let* ((early-secret (make-early-secret hash))
	 (derived-secret (make-hs-derived-secret early-secret :hash hash))
	 (hs-secret (make-hs-secret derived-secret shared-secret :hash hash))
	 (ssecret (make-hs-traffic-secret hs-secret hello-hash t :hash hash))
	 (server-key (make-hs-key ssecret :cipher cipher))
	 (server-iv (make-hs-iv ssecret :hash hash))
	 (csecret (make-hs-traffic-secret hs-secret hello-hash nil :hash hash))
	 (client-key (make-hs-key csecret :cipher cipher))
	 (client-iv (make-hs-iv csecret :hash hash)))
    #+debug
    (progn
      (format t "shared secret=~a~%" (ironclad:byte-array-to-hex-string shared-secret))
      (format t "early secret=~a~%" (ironclad:byte-array-to-hex-string early-secret))
      (format t "derived secret=~a~%" (ironclad:byte-array-to-hex-string derived-secret))
      (format t "handshake secret=~a~%" (ironclad:byte-array-to-hex-string hs-secret))
      (format t "csecret=~a~%" (ironclad:byte-array-to-hex-string csecret))
      (format t "ssecret=~a~%" (ironclad:byte-array-to-hex-string ssecret))
      (format t "server hs key=~a~%" (ironclad:byte-array-to-hex-string server-key))
      (format t "server iv=~a~%" (ironclad:byte-array-to-hex-string server-iv))
      (format t "client hs key=~a~%" (ironclad:byte-array-to-hex-string client-key))
      (format t "client iv=~a~%" (ironclad:byte-array-to-hex-string client-iv)))

    (values hs-secret ssecret server-key server-iv
	    csecret client-key client-iv)))

(defun application-key-schedule (handshake-secret handshake-hash &key (hash :sha384) (cipher :aes256))
  (let* ((derived-secret (make-hs-derived-secret handshake-secret :hash hash))
	 (master-secret (make-master-secret derived-secret :hash hash))
	 (ssecret (make-app-traffic-secret master-secret handshake-hash t :hash hash))
	 (server-key (make-app-traffic-key ssecret :hash hash :cipher cipher))
	 (server-iv (make-app-iv ssecret :hash hash))
	 (csecret (make-app-traffic-secret master-secret handshake-hash nil :hash hash))
	 (client-key (make-app-traffic-key csecret :hash hash :cipher cipher))
	 (client-iv (make-app-iv csecret :hash hash)))
    #+debug
    (progn
      (format t "handshake-secret=~a~%" (ironclad:byte-array-to-hex-string handshake-secret))
      (format t "app derived=~a~%" (ironclad:byte-array-to-hex-string derived-secret))
      (format t "master secret=~a~%" (ironclad:byte-array-to-hex-string master-secret))
      (format t "app server traffic secret=~a~%" (ironclad:byte-array-to-hex-string ssecret))
      (format t "app server traffic key=~a~%" (ironclad:byte-array-to-hex-string server-key))
      (format t "app server traffic iv=~a~%" (ironclad:byte-array-to-hex-string server-iv))
      (format t "app client traffic secret=~a~%" (ironclad:byte-array-to-hex-string csecret))
      (format t "app client traffic key=~a~%" (ironclad:byte-array-to-hex-string client-key))
      (format t "app client traffic iv=~a~%" (ironclad:byte-array-to-hex-string client-iv)))
    (values ssecret server-key server-iv
	    csecret client-key client-iv)))

(defun make-early-secret (hash)
  (hkdf-extract nil (make-zero-key hash) :hash hash))

(defun empty-digest (hash)
  (ironclad:produce-digest
   (ironclad:update-digest
    (ironclad:make-digest hash)
    (make-array 0 :element-type '(unsigned-byte 8)))))

(defun make-hs-derived-secret (early-secret &key (hash :sha384))
  (format t "derived secret from early hash=~a~%" (ironclad:byte-array-to-hex-string early-secret))
  (hkdf-expand-label early-secret "derived" (empty-digest hash) (hash-len hash) :hash hash))

(defun make-hs-secret (derived-secret shared-secret &key (hash :sha384))
  (hkdf-extract derived-secret shared-secret :hash hash))

(defun make-hs-traffic-secret (secret ctxhash server-p &key (hash :sha384))
  (let ((label (if server-p "s hs traffic" "c hs traffic")))
    (hkdf-expand-label secret label ctxhash (hash-len hash) :hash hash)))

(defun make-hs-key (secret &key (hash :sha384) (cipher :aes256))
  (hkdf-expand-label secret "key" (make-empty-array) (key-len cipher) :hash hash))

(defun make-hs-iv (secret &key (hash :sha384))
  (hkdf-expand-label secret "iv" (make-empty-array) 12 :hash hash))

(defun make-app-derived-secret (handshake-secret &optional &key (hash :sha384))
  (let ((empty-array (make-empty-array (hash-len hash)))
	(n (hash-len hash)))
    (hkdf-expand-label handshake-secret "derived" empty-array n :hash hash)))

(defun make-master-secret (derived-secret &optional &key (hash :sha384))
  (hkdf-extract derived-secret (make-zero-key hash) :hash hash))

(defun make-app-traffic-secret (master-secret ctxhash server-p &key (hash :sha384))
  (let ((tls-label (if server-p "s ap traffic" "c ap traffic")))
    (hkdf-expand-label master-secret tls-label ctxhash (hash-len hash) :hash hash)))

(defun make-app-traffic-key (secret &key (hash :sha384) (cipher :aes256))
  (hkdf-expand-label secret "key" (make-empty-array) (key-len cipher) :hash hash))

(defun make-app-iv (secret &key (hash :sha384))
  (hkdf-expand-label secret "iv" (make-empty-array) 12 :hash hash))
