module github.com/kyverno/kyverno-exporter

go 1.14

require (
	github.com/jinzhu/copier v0.2.3
	github.com/kyverno/kyverno v1.3.1
	github.com/prometheus/client_golang v1.9.0
	k8s.io/client-go v0.18.12
	sigs.k8s.io/controller-runtime v0.5.0
)

replace github.com/gorilla/rpc v1.2.0+incompatible => github.com/gorilla/rpc v1.2.0
