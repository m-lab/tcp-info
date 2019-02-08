package metrics_test

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"testing"

	"github.com/m-lab/tcp-info/metrics"
	"github.com/prometheus/prometheus/util/promlint"
)

func TestPrometheusMetrics(t *testing.T) {
	server := metrics.SetupPrometheus(0)
	defer server.Shutdown(nil)
	log.Println(server.Addr)

	metricReader, err := http.Get("http://" + server.Addr + "/metrics")
	if err != nil || metricReader == nil {
		t.Fatalf("Could not GET metrics: %v", err)
	}
	metricBytes, err := ioutil.ReadAll(metricReader.Body)
	if err != nil {
		t.Fatalf("Could not read metrics: %v", err)
	}
	metricsLinter := promlint.New(bytes.NewBuffer(metricBytes))
	problems, err := metricsLinter.Lint()
	if err != nil {
		t.Errorf("Could not lint metrics: %v", err)
	}
	for _, p := range problems {
		t.Errorf("Bad metric %v: %v", p.Metric, p.Text)
	}
}
