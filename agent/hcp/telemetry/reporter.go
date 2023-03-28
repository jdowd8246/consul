package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/consul/lib"
	"github.com/hashicorp/go-hclog"
)

const (
	defaultStreamTimeout  = time.Minute
	defaultReportInterval = 5 * time.Second
	defaultBatchInterval  = 10 * time.Second
)

type ReporterConfig struct {
	StreamTimeout  time.Duration
	ReportInterval time.Duration
	BatchInterval  time.Duration

	Logger hclog.Logger

	Gatherer lib.MetricsHandler
	Exporter Exporter
}

func DefaultConfig() *ReporterConfig {
	return &ReporterConfig{
		StreamTimeout:  defaultStreamTimeout,
		ReportInterval: defaultReportInterval,
		BatchInterval:  defaultBatchInterval,
	}
}

type Reporter struct {
	cfg ReporterConfig

	batchedMetrics map[time.Time]*metrics.IntervalMetrics
	flushCh        chan struct{}

	// Only used for test purposes to know when flush has occurred.
	testFlushCh chan struct{}
}

func NewReporter(cfg *ReporterConfig) (*Reporter, error) {
	if cfg.Exporter == nil || cfg.Gatherer == nil || cfg.Logger == nil {
		return nil, fmt.Errorf("metrics exporter, gatherer and logger must be provided")
	}

	r := &Reporter{
		cfg: *cfg,

		batchedMetrics: make(map[time.Time]*metrics.IntervalMetrics),
		flushCh:        make(chan struct{}, 1),
	}

	return r, nil
}

func (r *Reporter) Run(ctx context.Context) {
	r.cfg.Logger.Debug("HCP Metrics Reporter starting")

	// Not that timing will not be perfect since select will
	// pick a case that is ready via uniform pseudo-random selection
	// With this approach, we avoid worrying about concurrent access to resources.
	flushTimer := time.NewTicker(r.cfg.BatchInterval)
	defer flushTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-time.After(r.cfg.ReportInterval):
			r.gatherMetrics()

		case <-flushTimer.C:
			// Ensures we don't block if the flushCh is handling a signal.
			select {
			case r.flushCh <- struct{}{}:
			default:
			}

		case <-r.flushCh:
			flushTimer.Reset(r.cfg.BatchInterval)
			if err := r.flushMetrics(); err != nil {
				r.cfg.Logger.Error("Failed to flush metrics", "error", err)
			}

			if r.testFlushCh != nil {
				r.testFlushCh <- struct{}{}
			}
		}
	}
}

func (r *Reporter) gatherMetrics() {
	intervals := r.cfg.Gatherer.Data()
	if len(intervals) >= 1 {
		// Discard the current interval. We will wait until it is populated to gather it.
		intervals = intervals[:len(intervals)-1]
	}

	for _, interval := range intervals {
		// TODO: We can't fully avoid duplicates without infinite memory.
		if _, ok := r.batchedMetrics[interval.Interval]; ok {
			continue
		}
		// TODO: Bounded batchedMetrics check.
		// TODO: Do some testing for 100 batches, 200 batches, etc. (Get data information)
		// TODO: Fancy flushing, remove the oldest first (circular buffer): https://github.com/armon/circbuf
		r.batchedMetrics[interval.Interval] = interval
	}
}

func (r *Reporter) flushMetrics() error {
	metricsList := make([]*metrics.IntervalMetrics, 0)
	for interval, intervalMetrics := range r.batchedMetrics {
		if intervalMetrics != nil {
			metricsList = append(metricsList, intervalMetrics)
		}
		// TODO: only do this if there is no error. For now since the map is unbounded, leave it.
		r.batchedMetrics[interval] = nil
	}

	if len(metricsList) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.cfg.StreamTimeout)
	defer cancel()

	return r.cfg.Exporter.Export(ctx, metricsList)
}
