package metrics_test

import (
	"testing"

	"github.com/m-lab/go/prometheusx"

	"github.com/m-lab/tcp-info/metrics"
)

func TestPrometheusMetrics(t *testing.T) {
	metrics.ConnectionCountHistogram.WithLabelValues("x")
	metrics.ErrorCount.WithLabelValues("x")
	metrics.SyscallTimeHistogram.WithLabelValues("x")
	prometheusx.LintMetrics(t)
}
