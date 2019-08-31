(in-package :tls)

(defclass file-certificate ()
  ((path :type string :initform nil :initarg :path :accessor path)))

(defclass x509-certificate (file-certificate)
  ((encoding :type keyword :initform nil :initarg :encoding :accessor encoding)
   (bytes :initform nil :initarg :bytes :accessor bytes)))

(defun read-file (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((len (file-length in)))
      (let ((seq (make-array len :element-type '(unsigned-byte 8))))
	(read-sequence seq in)
	seq))))

(defun read-x509-certificate (path encoding)
  (let ((certbytes (read-file path)))
    (make-instance 'x509-certificate :encoding encoding :path path :bytes certbytes)))
