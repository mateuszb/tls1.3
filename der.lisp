(in-package :tls)

(defconstant +ASN.1-SEQUENCE-TAG+ 16)
(defconstant +ASN.1-INTEGER-TAG+ 2)

(defun read-id-octet (in)
  (read-byte in))

(defun decode-id-octet (o)
  (values
   (ldb (byte 2 6) o)
   (ldb (byte 1 5) o)
   (ldb (byte 5 0) o)))

(defun read-long-tag (in)
  (loop
     with octet = (read-byte in)
     with continue-p = (ldb (byte 1 7) octet)
     do
       (format t "octet = 0x~2,'0x~%" octet)
     while continue-p))

(defun read-type-tag (in)
  (let ((id-octet (read-id-octet in))
	(tag nil))
    (multiple-value-bind (class constructed-p short-tag) (decode-id-octet id-octet)
      (if (= short-tag #b11111)
	  (setf tag (read-long-tag in))
	  (setf tag short-tag))
      (values class constructed-p tag))))

(defun indefinite-form-p (o)
  (and (plusp (ldb (byte 1 7) o))
       (zerop (ldb (byte 7 0) o))))

(defun short-form-p (o)
  (zerop (ldb (byte 1 7) o)))

(defun long-form-p (o)
  (and (plusp (ldb (byte 1 7) o))
       (plusp (ldb (byte 7 0) o))))

(defun classify-length-octet (o)
  (cond
    ((indefinite-form-p o) :indefinite)
    ((short-form-p o) :short)
    ((long-form-p o) :long)))

(defun read-length (in)
  (let ((len-octet (read-byte in)))
    (case (classify-length-octet len-octet)
      (:indefinite nil)
      (:short (ldb (byte 7 0) len-octet))
      (:long
       (let* ((num-len-octets (ldb (byte 7 0) len-octet))
	      (total-bits (* num-len-octets 8)))
	 (loop
	    for i from 0 below num-len-octets
	    for j from (- total-bits 8) downto 0 by 8
	    with len = 0
	    do
	      (let ((octet (read-byte in)))
		(setf (ldb (byte 8 j) len)
		      (ldb (byte 8 0) octet)))
	    finally (return len)))))))

;; RSAPrivateKey ::= SEQUENCE {
;;        version           Version,
;;        modulus           INTEGER,  -- n
;;        publicExponent    INTEGER,  -- e
;;        privateExponent   INTEGER,  -- d
;;        prime1            INTEGER,  -- p
;;        prime2            INTEGER,  -- q
;;        exponent1         INTEGER,  -- d mod (p-1)
;;        exponent2         INTEGER,  -- d mod (q-1)
;;        coefficient       INTEGER,  -- (inverse of q) mod p
;;        otherPrimeInfos   OtherPrimeInfos OPTIONAL
;;    }

(defun read-integer (stream)
  (multiple-value-bind (class constructed-p tag) (read-type-tag stream)
    (assert (and (= class 0) (= constructed-p 0) (= tag 2)))
    (let ((length (read-length stream)))
      (loop
	 for i from 0 below length
	 for j from (* 8 (1- length)) downto 0 by 8
	 with val = 0
	 do (setf (ldb (byte 8 j) val) (read-byte stream))
	 finally (return val)))))

(defun load-private-key-der (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (multiple-value-bind (class constructed-p tag) (read-type-tag in)
      (assert (and (= class 0) (and (= constructed-p 1)) (= tag +ASN.1-SEQUENCE-TAG+)))
      (let ((length (read-length in))
	    (version (read-integer in))
	    (modulus (read-integer in))
	    (public-exponent (read-integer in))
	    (private-exponent (read-integer in))
	    (prime1 (read-integer in))
	    (prime2 (read-integer in))
	    (exponent1 (read-integer in))
	    (exponent2 (read-integer in))
	    (coeff (read-integer in)))
	(declare (ignorable length public-exponent prime1 prime2 exponent1 exponent2 coeff))
	(assert (zerop version))
	(ironclad:make-private-key :rsa :n modulus :d private-exponent)))))

(defun round-up (n power-of-2)
  (logand (+ n (1- power-of-2)) (lognot (1- power-of-2))))

(defun bits-per-number (x)
  (1+ (floor (log x 2))))

(defun bytes-per-number (x)
  (/
   (round-up
    (bits-per-number x) 8)
   8))


;; TODO: is this needed?
#+off(defun number->byte-array (n &optional size)
  (let ((len (if size size (bytes-per-number n))))
    (let ((arr (make-array len :element-type '(unsigned-byte 8) :initial-element 0)))
      (loop
	 for i from (* (1- bytes-per-number) 8) downto 0 by 8
	 for j from 0 below 
	 do
	   (setf (aref arr ))))
    ))
