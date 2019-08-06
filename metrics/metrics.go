// Package metrics defines prometheus metric types and provides convenience
// methods to add accounting to various parts of the pipeline.
//
// When defining new operations or metrics, these are helpful values to track:
//  - things coming into or go out of the system: requests, files, tests, api calls.
//  - the success or error status of any of the above.
//  - the distribution of processing latency.
package metrics

import (
	"log"
	"math"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// SyscallTimeHistogram tracks the latency in the syscall.  It does NOT include
	// the time to process the netlink messages.
	SyscallTimeHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "tcpinfo_syscall_time_histogram",
			Help: "netlink syscall latency distribution (seconds)",
			Buckets: []float64{
				0.001, 0.00125, 0.0016, 0.002, 0.0025, 0.0032, 0.004, 0.005, 0.0063, 0.0079,
				0.01, 0.0125, 0.016, 0.02, 0.025, 0.032, 0.04, 0.05, 0.063, 0.079,
				0.1, 0.125, 0.16, 0.2,
			},
		},
		[]string{"af"})

	// PollingHistogram tracks the interval between polling cycles.
	PollingHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "tcpinfo_polling_interval_histogram",
			Help:    "netlink polling interval distribution (seconds)",
			Buckets: prometheus.LinearBuckets(0, .001, 20),
		},
	)

	// ConnectionCountHistogram tracks the number of connections returned by
	// each syscall.  This ??? includes local connections that are NOT recorded
	// in the cache or output.
	// TODO - convert this to integer bins.
	ConnectionCountHistogram = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "tcpinfo_connection_count_histogram",
			Help: "connection count histogram",
			Buckets: []float64{
				1, 2, 3, 4, 5, 6, 8,
				10, 12.5, 16, 20, 25, 32, 40, 50, 63, 79,
				100, 125, 160, 200, 250, 320, 400, 500, 630, 790,
				1000, 1250, 1600, 2000, 2500, 3200, 4000, 5000, 6300, 7900,
				10000, 12500, 16000, 20000, 25000, 32000, 40000, 50000, 63000, 79000,
				10000000,
			},
		},
		[]string{"af"})

	// CacheSizeHistogram tracks the number of entries in connection cache.
	// TODO - convert this to integer bins.
	CacheSizeHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name: "tcpinfo_cache_count_histogram",
			Help: "cache connection count histogram",
			Buckets: []float64{
				1, 2, 3, 4, 5, 6, 8,
				10, 12.5, 16, 20, 25, 32, 40, 50, 63, 79,
				100, 125, 160, 200, 250, 320, 400, 500, 630, 790,
				1000, 1250, 1600, 2000, 2500, 3200, 4000, 5000, 6300, 7900,
				10000, 12500, 16000, 20000, 25000, 32000, 40000, 50000, 63000, 79000,
				10000000,
			},
		})

	// ErrorCount measures the number of errors
	// Provides metrics:
	//    tcpinfo_Error_Count
	// Example usage:
	//    metrics.ErrorCount.With(prometheus.Labels{"type", "foobar"}).Inc()
	ErrorCount = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcpinfo_error_total",
			Help: "The total number of errors encountered.",
		}, []string{"type"})

	// NewFileCount counts the number of connection files written.
	//
	// Provides metrics:
	//   tcpinfo_new_file_count
	// Example usage:
	//   metrics.FileCount.Inc()
	NewFileCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "tcpinfo_new_file_total",
			Help: "Number of files created.",
		},
	)

	// SendRateHistogram tracks the 1 second average TCP send rate from a namespace.
	// The count field should increment at 60 counts per minute.
	// The sum field will show the total bits sent over time from this namespace.
	// NOTE: The total may be slightly less than actual, since polling may miss some bytes at the end
	// of a connection.
	SendRateHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name: "tcpinfo_send_rate_histogram",
			Help: "send rate histogram",
			Buckets: []float64{
				0, // We don't really care about small rates, so we use course measurement below 10Kbps.
				1, 10, 100, 1000,
				10000, 12600, 15800, 20000, 25100, 31600, 39800, 50100, 63100, 79400,
				100000, 126000, 158000, 200000, 251000, 316000, 398000, 501000, 631000, 794000,
				1000000, 1260000, 1580000, 2000000, 2510000, 3160000, 3980000, 5010000, 6310000, 7940000,
				10000000, math.Inf(+1),
			},
		})
	// ReceiveRateHistogram tracks the 1 second average TCP send rate from a namespace.
	// The count field should increment at 60 counts per minute.
	// The sum field will show the total bits received over time in this namespace.
	// NOTE: The total may be slightly less than actual, since polling may miss some bytes at the end
	// of a connection.
	ReceiveRateHistogram = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name: "tcpinfo_receive_rate_histogram",
			Help: "receive rate histogram",
			Buckets: []float64{
				0, // We don't really care about small rates, so we use course measurement below 10Kbps.
				1, 10, 100, 1000,
				10000, 12600, 15800, 20000, 25100, 31600, 39800, 50100, 63100, 79400,
				100000, 126000, 158000, 200000, 251000, 316000, 398000, 501000, 631000, 794000,
				1000000, 1260000, 1580000, 2000000, 2510000, 3160000, 3980000, 5010000, 6310000, 7940000,
				10000000, math.Inf(+1),
			},
		})

	// SnapshotCount counts the total number of snapshots collected across all connections.
	SnapshotCount = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "tcpinfo_snapshot_total",
			Help: "Number of snapshots taken.",
		},
	)
)

// init() prints a log message to let the user know that the package has been
// loaded and the metrics registered. The metrics are auto-registered, which
// means they are registered as soon as this package is loaded, and the exact
// time this occurs (and whether this occurs at all in a given context) can be
// opaque.
func init() {
	log.Println("Prometheus metrics in tcp-info.metrics are registered.")
}
