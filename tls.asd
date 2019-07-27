(defsystem "socket"
  :version "0.1.0"
  :author "Mateusz Berezecki"
  :license "BSD"
  :components ((:file "packages")
	       (:file "tls" :depends-on ("packages")))
  :in-order-to ((test-op (test-op "tls/tests")))
  :description "A lightweight minimal tls1.3 library that is easy to integrate.")

(defsystem "tls/tests"
  :depends-on ("prove")
  :defsystem-depends-on (:prove-asdf)
  :serial t
  :components ((:module "tests" :components ((:test-file "test"))))
  :perform (test-op :after (o c)
		    (funcall (intern #. (string :run) :prove) c)))
