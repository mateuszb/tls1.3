(defsystem "tls"
  :version "0.1.0"
  :author "Mateusz Berezecki"
  :license "BSD"
  :depends-on ("flexi-streams")
  :components ((:file "packages")
	       (:file "constants" :depends-on ("packages"))
	       (:file "tls" :depends-on ("messages"))
	       (:file "messages" :depends-on ("packages" "constants")))
  :in-order-to ((test-op (test-op "tls/tests")))
  :description "A lightweight minimal tls1.3 library that is easy to integrate.")

(defsystem "tls/tests"
  :depends-on ("prove" "flexi-streams")
  :defsystem-depends-on (:prove-asdf)
  :serial t
  :components ((:module "tests" :components ((:test-file "test"))))
  :perform (test-op :after (o c)
		    (funcall (intern #. (string :run) :prove) c)))
