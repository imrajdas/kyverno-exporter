package main

import (
	"encoding/json"
	"fmt"
	v1 "github.com/kyverno/kyverno/pkg/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/api/policyreport/v1alpha1"
	client "github.com/kyverno/kyverno/pkg/dclient"
	"github.com/kyverno/kyverno/pkg/signal"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"net/http"
	"time"

	logger "sigs.k8s.io/controller-runtime/pkg/log"
)

type KyvernoCollector struct {
	tc_violations *prometheus.Desc
	no_violation_on_audit_mode *prometheus.Desc
	no_violation_on_enforce_mode *prometheus.Desc
	tc_successful_policy_application *prometheus.Desc
	no_audit_policies *prometheus.Desc
}

func createClientConfig(kubeconfig string) (*rest.Config, error) {
	logger := logger.Log
	if kubeconfig == "" {
		logger.Info("Using in-cluster configuration")
		return rest.InClusterConfig()
	}
	logger.Info(fmt.Sprintf("Using configuration from '%s'", kubeconfig))
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

var stopCh = signal.SetupSignalHandler()
// create client config
var clientConfig, _ = createClientConfig("")

var Client,  err = client.NewClient(clientConfig, 15*time.Minute, stopCh, logger.Log)

//You must create a constructor for you collector that
//initializes every descriptor and returns a pointer to the collector
func newKyvernoCollector() *KyvernoCollector {
	return &KyvernoCollector{
		tc_violations: prometheus.NewDesc("kyverno_total_count_of_violations",
			"Shows total count of violation",
			nil, nil,
		),
		no_violation_on_audit_mode: prometheus.NewDesc("kyverno_no_violation_on_audit_mode",
			"Shows total number of violation on audit mode",
			nil, nil,
		),
		no_violation_on_enforce_mode: prometheus.NewDesc("kyverno_no_violation_on_enforce_mode",
			"Shows total number of violation on enforce mode",
			nil, nil,
		),
		no_audit_policies: prometheus.NewDesc("kyverno_number_of_audit_policies",
			"Shows total number of audit policies",
			nil, nil,
		),
		tc_successful_policy_application: prometheus.NewDesc("kyverno_tc_successful_policy_application",
			"Shows total count of successful policy application",
			nil, nil,
		),
	}
}

//Each and every collector must implement the Describe function.
//It essentially writes all descriptors to the prometheus desc channel.
func (collector *KyvernoCollector) Describe(ch chan<- *prometheus.Desc) {

	// Update thtotalPassKeyverois section with the each metric you create for a given collector
	ch <- collector.tc_violations
	ch <- collector.no_audit_policies
	ch <- collector.tc_successful_policy_application
	ch <- collector.no_violation_on_audit_mode
	ch <- collector.no_violation_on_enforce_mode
}


func getTCViolation() (float64, error){

	pr, err := Client.ListResource("", "PolicyReport", "", nil)
	if err != nil {
		return 0, err
	}

	var total_violation float64 = 0
	var newPR v1alpha1.PolicyReport

	for _, report := range pr.Items {
		marshalObj, err := json.Marshal(report.Object)
		if err != nil {
			return 0, nil
		}

		json.Unmarshal(marshalObj, &newPR)

		if newPR.Summary.Fail > 0 {
			total_violation += float64(newPR.Summary.Fail)
		}
	}

	return total_violation, nil
}

func getTotalAuditPolicies() (float64, error){

	cp, err := Client.ListResource("", "ClusterPolicy", "", nil)
	if err != nil {
		return 0, err
	}

	var total_audit_policies float64 = 0
	var newCP v1.ClusterPolicy

	for _, report := range cp.Items {
		marshalObj, err := json.Marshal(report.Object)
		if err != nil {
			return 0, nil
		}

		json.Unmarshal([]byte(marshalObj), &newCP)

		if newCP.Spec.ValidationFailureAction == "audit" {
			total_audit_policies += 1
		}
	}

	return total_audit_policies, nil
}

func totalSuccesfulApplicationPolicy() (float64, error){
	pr, err := Client.ListResource("", "PolicyReport", "", nil)
	if err != nil {
		return 0, err
	}

	var tc_successfull_policy_application float64 = 0
	var newPR v1alpha1.PolicyReport

	for _, report := range pr.Items {
		marshalObj, err := json.Marshal(report.Object)
		if err != nil {
			return 0, nil
		}

		json.Unmarshal(marshalObj, &newPR)

		if newPR.Summary.Pass > 0 {
			tc_successfull_policy_application += float64(newPR.Summary.Pass)
		}
	}

	return tc_successfull_policy_application, nil

}

func ViolationCountOnEnforceMode() (float64, error) {
	pr, err := Client.ListResource("", "PolicyReport", "", nil)
	if err != nil {
		return 0, err
	}

	var total_violation_on_enforce_mode float64 = 0
	var newPR v1alpha1.PolicyReport

	for _, report := range pr.Items {
		marshalObj, err := json.Marshal(report.Object)
		if err != nil {
			return 0, nil
		}

		json.Unmarshal([]byte(marshalObj), &pr)

		if newPR.Summary.Fail > 0 {
			for _, result := range newPR.Results {
				if result.Status == "fail" {
					getcp, err := Client.GetResource("","ClusterPolicy", "", result.Policy)
					if err != nil {
						return 0, err
					}

					var cp v1.ClusterPolicy

					marshalObj, err := json.Marshal(getcp.Object)
					if err != nil {
						return 0, nil
					}

					json.Unmarshal([]byte(marshalObj), &cp)
					if cp.Spec.ValidationFailureAction == "enforce" {
						total_violation_on_enforce_mode += 1
					}
				}
			}
		}
	}

	return total_violation_on_enforce_mode, nil
}

func ViolationCountOnAuditMode() (float64, error) {
	cpolrs, err := Client.ListResource("", "PolicyReport", "", nil)
	if err != nil {
		return 0, err
	}

	var total_violation_on_audit_mode float64 = 0
	var pr v1alpha1.PolicyReport

	for _, report := range cpolrs.Items {
		marshalObj, err := json.Marshal(report.Object)
		if err != nil {
			return 0, nil
		}

		json.Unmarshal([]byte(marshalObj), &pr)

		if pr.Summary.Fail > 0 {
			for _, result := range pr.Results {
				if result.Status == "fail" {
					getcp, err := Client.GetResource("","ClusterPolicy", "", result.Policy)
					if err != nil {
						return 0, err
					}

					var cp v1.ClusterPolicy

					marshalObj, err := json.Marshal(getcp.Object)
					if err != nil {
						return 0, nil
					}

					json.Unmarshal([]byte(marshalObj), &cp)
					if cp.Spec.ValidationFailureAction == "enforce" {
						total_violation_on_audit_mode += 1
					}
				}
			}
		}
	}

	return total_violation_on_audit_mode, nil
}

//Collect implements required collect function for all promehteus collectors
func (collector *KyvernoCollector) Collect(ch chan<- prometheus.Metric) {
	//Write latest value for each metric in the prometheus metric channel.
	//Note that you can pass CounterValue, GaugeValue, or UntypedValue types here.
	tc_violation, _ := getTCViolation()
	audit_policies, _ := getTotalAuditPolicies()
	tc_successfull_policy_application, _ := totalSuccesfulApplicationPolicy()
	total_violation_on_enforce_mode, _ := ViolationCountOnEnforceMode()
	total_violation_on_audit_mode, _ := ViolationCountOnAuditMode()

	ch <- prometheus.MustNewConstMetric(collector.tc_violations, prometheus.CounterValue, tc_violation)
	ch <- prometheus.MustNewConstMetric(collector.no_audit_policies, prometheus.CounterValue, audit_policies)
	ch <- prometheus.MustNewConstMetric(collector.tc_successful_policy_application, prometheus.CounterValue, tc_successfull_policy_application)
	ch <- prometheus.MustNewConstMetric(collector.no_violation_on_enforce_mode, prometheus.CounterValue, total_violation_on_enforce_mode)
	ch <- prometheus.MustNewConstMetric(collector.no_violation_on_audit_mode, prometheus.CounterValue, total_violation_on_audit_mode)
}

func main() {
	kyverno := newKyvernoCollector()
	prometheus.MustRegister(kyverno)

	//This section will start the HTTP server and expose
	//any metrics on the /metrics endpoint.
	http.Handle("/metrics", promhttp.Handler())
	log.Print("Beginning to serve on port :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
