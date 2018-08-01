// The metrics package defines prometheus metric types and provides
// convenience methods to add accounting to various parts of the pipeline.
//
// When defining new operations or metrics, these are helpful values to track:
//  - things coming into or go out of the system: requests, files, tests, api calls.
//  - the success or error status of any of the above.
//  - the distribution of processing latency.
package metrics

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func SetupPrometheus(promPort int) {
	if promPort <= 0 {
		log.Println("Not exporting prometheus metrics")
		return
	}

	// Define a custom serve mux for prometheus to listen on a separate port.
	// We listen on a separate port so we can forward this port on the host VM.
	// We cannot forward port 8080 because it is used by AppEngine.
	mux := http.NewServeMux()
	// Assign the default prometheus handler to the standard exporter path.
	mux.Handle("/metrics", promhttp.Handler())
	// Assign the pprof handling paths to the external port to access individual
	// instances.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	prometheus.MustRegister(FetchTimeMsecSummary)
	prometheus.MustRegister(ConnectionCountSummary)
	prometheus.MustRegister(CacheSizeSummary)

	prometheus.MustRegister(EntryFieldCountHistogram)
	prometheus.MustRegister(FileSizeHistogram)
	prometheus.MustRegister(RowSizeHistogram)

	// Common metrics
	prometheus.MustRegister(FileCount)
	prometheus.MustRegister(ErrorCount)
	prometheus.MustRegister(WarningCount)

	port := fmt.Sprintf(":%d", promPort)
	log.Println("Exporting prometheus metrics on", port)
	go http.ListenAndServe(port, mux)
}

var (
	// FetchTimeMsecSummary measures the latency (in msec) to fetch tcp-info records from kernel.
	// Provides metrics:
	//    tcpinfo_Fetch_Time_Msec_Summary
	// Example usage:
	//    metrics.FetchTimeMsecSummary.With(prometheus.Labels{"af": "ipv6"}).observe(float64)
	FetchTimeMsecSummary = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name: "tcpinfo_Fetch_Time_Msec_Summary",
		Help: "The total time to fetch tcp-info records, in milliseconds.",
	}, []string{"af"})

	// ConnectionCountSummary the (total) number of TCP connections collected, by type.
	// Provides metrics:
	//    tcpinfo_Connection_Count_Summary
	// Example usage:
	//    metrics.ConnectionCountSummary.With(prometheus.Labels{"af": "ipv6"}).observe(float64)
	ConnectionCountSummary = prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name: "tcpinfo_Connection_Count_Summary",
		Help: "The (total) number of TCP connections collected, by type.",
	}, []string{"af"})

	// CacheSizeSummary measures the size of the connection cache.
	// Provides metrics:
	//    tcpinfo_Cache_Size_Summary
	// Example usage:
	//    metrics.CacheSizeSummary.observe()
	CacheSizeSummary = prometheus.NewSummary(prometheus.SummaryOpts{
		Name: "tcpinfo_Connection_Cache_Size_Summary",
		Help: "The number of entries in the connection cache.",
	})

	// ErrorCount measures the number of annotation errors
	// Provides metrics:
	//    tcpinfo_Error_Count
	// Example usage:
	//    metrics.ErrorCount.With(prometheus.Labels{"source", "foobar"}).Inc()
	ErrorCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcpinfo_Error_Count",
			Help: "The total number of errors encountered.",
		}, []string{"source"})

	// WarningCount measures the number of annotation warnings
	// Provides metrics:
	//    tcpinfo_Warning_Count
	// Example usage:
	//    metrics.WarningCount.With(prometheus.Labels{"source", "foobar"}).Inc()
	WarningCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tcpinfo_Warning_Count",
			Help: "The total number of Warnings encountered.",
		}, []string{"source"})

	// FileCount counts the number of files written.
	//
	// Provides metrics:
	//   tcpinfo_New_File_Count
	// Example usage:
	//   metrics.FileCount.Inc()
	FileCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "tcpinfo_New_File_Count",
			Help: "Number of files created.",
		},
	)

	// TODO(dev): bytes/row - generalize this metric for any file type.
	//
	// RowSizeHistogram provides a histogram of bq row json sizes.  It is intended primarily for
	// NDT, so the bins are fairly large.  NDT average json is around 200K
	//
	// Provides metrics:
	//   etl_row_json_size_bucket{table="...", le="..."}
	//   ...
	//   etl_row_json_size_sum{table="...", le="..."}
	//   etl_row_json_size_count{table="...", le="..."}
	// Usage example:
	//   metrics.RowSizeHistogram.WithLabelValues(
	//           "ndt").Observe(len(json))
	RowSizeHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "etl_row_json_size",
			Help: "Row json size distributions.",
			Buckets: []float64{
				100, 200, 400, 800, 1600, 3200, 6400, 10000, 20000,
				40000, 80000, 160000, 320000, 500000, 600000, 700000,
				800000, 900000, 1000000, 1200000, 1500000, 2000000, 5000000,
			},
		},
		[]string{"table"},
	)

	// TODO(dev): rows/test - generalize this metric for any file type.
	//
	// EntryFieldCountHistogram provides a histogram of (approximate) row field counts.  It is intended primarily for
	// NDT, so the bins are fairly large.  NDT snapshots typically total about 10k
	// fields, 99th percentile around 35k fields, and occasionally as many as 50k.
	// Smaller field count bins included so that it is possibly useful for other
	// parsers.
	//
	// Provides metrics:
	//   etl_entry_field_count_bucket{table="...", le="..."}
	//   ...
	//   etl_entry_field_count_sum{table="...", le="..."}
	//   etl_entry_field_count_count{table="...", le="..."}
	// Usage example:
	//   metrics.EntryFieldCountHistogram.WithLabelValues(
	//           "ndt").Observe(fieldCount)
	EntryFieldCountHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "etl_entry_field_count",
			Help: "total snapshot field count distributions.",
			Buckets: []float64{
				1, 2, 3, 4, 6, 8,
				10, 12, 15, 20, 24, 30, 40, 48, 60, 80,
				100, 120, 150, 200, 240, 300, 400, 480, 600, 800,
				1000, 1200, 1500, 2000, 2400, 3000, 4000, 4800, 6000, 8000,
				10000, 12000, 15000, 20000, 24000, 30000, 40000, 48000, 60000, 80000,
				100000, 120000, 150000, 200000, 240000, 300000, 400000, 480000,
			},
		},
		[]string{"table"},
	)

	// FileSizeHistogram provides a histogram of source file sizes. The bucket
	// sizes should cover a wide range of input file sizes.
	//
	// Example usage:
	//   metrics.FileSizeHistogram.WithLabelValues(
	//       "ndt", "c2s_snaplog", "parsed").Observe(size)
	FileSizeHistogram = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "etl_test_file_size_bytes",
			Help: "Size of individual test files.",
			Buckets: []float64{
				0,
				1000,       // 1k
				5000,       // 5k
				10000,      // 10k
				25000,      // 25k
				50000,      // 50k
				75000,      // 75k
				100000,     // 100k
				200000,     // 200k
				300000,     // 300k
				400000,     // 400k
				500000,     // 500k
				600000,     // 600k
				700000,     // 700k
				800000,     // 800k
				900000,     // 900k
				1000000,    // 1 mb
				1100000,    // 1.1 mb
				1200000,    // 1.2 mb
				1400000,    // 1.4 mb
				1600000,    // 1.6 mb
				1800000,    // 1.8 mb
				2000000,    // 2.0 mb
				2400000,    // 2.4 mb
				2800000,    // 2.8 mb
				3200000,    // 3.2 mb
				3600000,    // 3.6 mb
				4000000,    // 4 mb
				6000000,    // 6 mb
				8000000,    // 8 mb
				10000000,   // 10 mb
				20000000,   // 20
				40000000,   // 40
				80000000,   // 80
				100000000,  // 100 mb
				200000000,  // 200
				400000000,  // 400
				800000000,  // 800
				1000000000, // 1 gb
				math.Inf(+1),
			},
		},
		[]string{"table", "kind", "group"},
	)
)
