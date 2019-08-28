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

(defun hkdf-extract (hash salt ikm)
  (etypecase salt
    (string
     (format t "string case~%")
     (compute-hmac hash (ironclad:ascii-string-to-byte-array salt) ikm))
    (array
     (format t "array case. salt=~a~%" (ironclad:byte-array-to-hex-string salt))
     (compute-hmac hash salt ikm))

    (null
     (format t "null case~%") (compute-hmac hash (make-empty-array 0) ikm))))

(defun hkdf-expand (hash prk info len)
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

(defun empty-digest (hash)
  (ironclad:produce-digest
   (ironclad:update-digest
    (ironclad:make-digest hash)
    (make-array 0 :element-type '(unsigned-byte 8)))))

(defun make-zero-key (hash)
  (make-empty-array (hash-len hash)))

(define-binary-class hkdf-label ()
  ((len u16)
   (label (varbytes :size-type 'u8))
   (context (varbytes :size-type 'u8))))

(defun make-empty-array (&optional (size 0))
  (make-array size :element-type '(unsigned-byte 8)))

(defun get-hkdf-label-as-bytes (hash label ctx len)
  (flexi-streams:with-output-to-sequence (out :element-type '(unsigned-byte 8))
    (let ((hkdf (make-instance 'hkdf-label
			       :len len
			       :label (ironclad:ascii-string-to-byte-array
				       (format nil "tls13 ~a" label))
			       :context ctx)))
      (write-value 'hkdf-label out hkdf))))

(defun early-secret (hash)
  (hkdf-extract hash nil (make-zero-key hash)))

(defun hkdf-expand-label (hash secret label ctx len)
  (let* ((hkdf-bytes
	  (make-array (+ 2 1 1 6 (length label) (length ctx))
		      :element-type '(unsigned-byte 8)
		      :initial-contents
		      (get-hkdf-label-as-bytes hash label ctx len))))
    (hkdf-expand hash secret hkdf-bytes len)))

(defun key-calculations (hash shared-secret hello-hash)
  (let* ((early-secret (early-secret hash))
	 (empty-hash (empty-digest hash))
	 (derived-secret (hkdf-expand-label hash early-secret "derived" empty-hash (hash-len hash)))
	 (handshake-secret (hkdf-extract hash derived-secret shared-secret))
	 (csecret (hkdf-expand-label hash handshake-secret "c hs traffic" hello-hash (hash-len hash)))
	 (ssecret (hkdf-expand-label hash handshake-secret "s hs traffic" hello-hash (hash-len hash)))
	 (client-hs-key (hkdf-expand-label hash csecret "key" (make-empty-array) 32))
	 (server-hs-key (hkdf-expand-label hash ssecret "key" (make-empty-array) 32))
	 (client-hs-iv (hkdf-expand-label hash csecret "iv" (make-empty-array) 12))
	 (server-hs-iv (hkdf-expand-label hash ssecret "iv" (make-empty-array) 12)))
    (format t "shared secret=~a~%" (ironclad:byte-array-to-hex-string shared-secret))
    (format t "early secret=~a~%" (ironclad:byte-array-to-hex-string early-secret))
    (format t "empty hash=~a~%" (ironclad:byte-array-to-hex-string empty-hash))
    (format t "derived secret=~a~%" (ironclad:byte-array-to-hex-string derived-secret))
    (format t "handshake secret=~a~%" (ironclad:byte-array-to-hex-string handshake-secret))
    (format t "csecret=~a~%" (ironclad:byte-array-to-hex-string csecret))
    (format t "ssecret=~a~%" (ironclad:byte-array-to-hex-string ssecret))
    (format t "client hs key=~a~%" (ironclad:byte-array-to-hex-string client-hs-key))
    (format t "server hs key=~a~%" (ironclad:byte-array-to-hex-string server-hs-key))
    (format t "client iv=~a~%" (ironclad:byte-array-to-hex-string client-hs-iv))
    (format t "server iv=~a~%" (ironclad:byte-array-to-hex-string server-hs-iv))
    (values ssecret server-hs-key server-hs-iv
	    csecret client-hs-key client-hs-iv)))
