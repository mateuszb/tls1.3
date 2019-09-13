(in-package :tls)

(define-condition no-common-cipher () ())

(define-condition alert-arrived (error)
  ((alert :initform nil :initarg :alert)))
