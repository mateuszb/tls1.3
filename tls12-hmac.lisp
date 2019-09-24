(in-package :tls)

(defun join-arrays (a b)
  (concatenate '(vector (unsigned-byte 8)) a b))

(defun tls-p (secret seed rounds)
  (format t "secret length = ~a~%" (length secret))
  (format t "seed = ~a~%" seed)
  (format t "rounds = ~a~%" rounds)
  (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
    (loop for i from 0 below rounds
       with a = seed
       do
	 (format t "a type = ~a~%" (type-of a))
	 (setf a (compute-hmac :sha384 secret a))
	 (write-sequence
	  (compute-hmac :sha384 secret (join-arrays a seed)) s))))

(defun tls-prf (secret label seed rounds)
  (let ((seq (join-arrays label seed)))
    (tls-p secret seq rounds)))

(defun tls12-master-key (premaster-secret client-random server-random)
  (tls-prf
   premaster-secret
   (map '(vector (unsigned-byte 8)) #'char-code "master secret")
   (concatenate
    '(vector (unsigned-byte 8)) client-random server-random) 1))

(defun tls12-final-key (master-secret server-random client-random)
  (let* ((cr client-random)
	 (sr server-random)
	 (label-bytes (map '(vector (unsigned-byte 8)) #'char-code "key expansion"))
	 (seed (concatenate
		'(vector (unsigned-byte 8)) sr cr)))
    (tls-prf master-secret label-bytes seed 4)))
