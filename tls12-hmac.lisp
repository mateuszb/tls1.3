(in-package :tls)

(declaim (optimize (debug 3) (speed 0)))
(defun join-arrays (a b)
  (concatenate '(vector (unsigned-byte 8)) a b))

(defun tls-p (secret seed rounds)
  (declare (optimize (speed 0) (debug 3)))
  (format t "secret length = ~a~%" (length secret))
  (format t "seed = ~a~%" seed)
  (format t "rounds = ~a~%" rounds)
  (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
    (loop for i from 0 below rounds
       with a = seed
       do
	 (setf a (compute-hmac :sha384 secret a))
	 (write-sequence
	  (compute-hmac :sha384 secret (join-arrays a seed)) s))))

(defun tls-prf (secret label seed rounds)
  (let ((seq (join-arrays label seed)))
    (let ((tmp (tls-p secret seq rounds)))
      (let ((arr (make-array (length tmp) :element-type '(unsigned-byte 8))))
	(loop for x across tmp
	   for i from 0 below (length tmp)
	   do (setf (aref arr i) x))
	arr))))

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
	 (seed (concatenate '(vector (unsigned-byte 8)) sr cr)))
    (tls-prf master-secret label-bytes seed 2)))

(defun tls12-finished-hash (master-secret handshake-digest)
  (let* ((label-bytes (map '(vector (unsigned-byte 8)) #'char-code "client finished")))
    (tls-prf master-secret label-bytes handshake-digest 1)))

(defun tls12-key-schedule (final-key)
  (values
   (subseq final-key 0 32)
   (subseq final-key 32 64)
   (subseq final-key 64 68)
   (subseq final-key 68 72)))
