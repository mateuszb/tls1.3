(in-package :tls)

(define-condition no-common-cipher () ())

(define-condition alert-arrived (error)
  ((alert :initform nil :initarg :alert)))

(defmethod print-object ((condition alert-arrived) stream)
  (print-unreadable-object (condition stream :type t)
    (with-slots (alert) condition
      (with-slots (level description) alert
	(format stream "level=~a, description=~a" level description)))))
