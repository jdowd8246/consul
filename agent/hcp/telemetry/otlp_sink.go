package telemetry

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-metrics"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/instrument"
	metricsdk "go.opentelemetry.io/otel/sdk/metric"
)

var (
	// This should likely be a store, but sync.Map could also be fine since the
	// maximum size of this will be the number of gauge metrics in Consul.
	gaugesGlobalStore sync.Map
	spaceReplacer     = strings.NewReplacer(" ", "_")
)

type OTLPSink struct {
	ctx context.Context

	meter         metric.Meter
	meterProvider *metricsdk.MeterProvider

	// OpenTelemetry instruments which allow us to record metric measurement.
	counterInstruments   sync.Map // map[string]*instrument.Float64Counter
	gaugeInstruments     sync.Map // map[string]*instrument.Float64ObservableGauge
	histogramInstruments sync.Map // map[string]*instrument.Float64Histogram
}

func NewOTLPSink() (*OTLPSink, error) {
	ctx := context.Background()

	// TODO: Create a custom exporter (interface)
	// We would create our custom exporter that uses a client that can do HCP auth.
	// The custom exporter would also be in charge of the batching strategy.
	exp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithInsecure(), otlpmetrichttp.WithEndpoint("localhost:9090"), otlpmetrichttp.WithTemporalitySelector(metricsdk.DefaultTemporalitySelector))
	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %v", err)
	}

	reader := metricsdk.NewPeriodicReader(exp, metricsdk.WithInterval(10*time.Second))
	provider := metricsdk.NewMeterProvider(metricsdk.WithReader(reader))
	meter := provider.Meter("github.com/consul/agent/hcp/telemetry")

	s := &OTLPSink{
		ctx: ctx,

		meter:         meter,
		meterProvider: provider,

		// Lazy loading when pushing metrics.
		// Size of these bounded by the number of Consul metrics of each category
		counterInstruments:   sync.Map{},
		gaugeInstruments:     sync.Map{},
		histogramInstruments: sync.Map{},
	}

	return s, nil
}

func (s *OTLPSink) Shutdown() {
	ctx := context.Background()
	s.meterProvider.Shutdown(ctx)
}

func (s *OTLPSink) SetGauge(key []string, val float32) {
	s.SetGaugeWithLabels(key, val, nil)
}

func (s *OTLPSink) SetGaugeWithLabels(key []string, val float32, labels []metrics.Label) {
	// TODO: Handle labels and metric filtering.
	k := s.flattenKey(key)
	gauge, ok := s.gaugeInstruments.Load(k)
	gaugesGlobalStore.Store(k, float64(val))

	if !ok {
		g, _ := s.meter.Float64ObservableGauge(k)
		s.gaugeInstruments.Store(k, &g)
		gauge = &g
		s.meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
			if val, ok := gaugesGlobalStore.LoadAndDelete(k); ok {
				o.ObserveFloat64(*(gauge.(*instrument.Float64ObservableGauge)), val.(float64))
			}
			return nil
		}, *(gauge.(*instrument.Float64ObservableGauge)))
	}
}

// EmitKey is not implemented.
func (s *OTLPSink) EmitKey(key []string, val float32) {
}

func (s *OTLPSink) IncrCounter(key []string, val float32) {
	s.IncrCounterWithLabels(key, val, nil)
}

func (s *OTLPSink) IncrCounterWithLabels(key []string, val float32, labels []metrics.Label) {
	// TODO: Handle labels and metric filtering.
	k := s.flattenKey(key)
	counter, ok := s.counterInstruments.Load(k)
	if !ok {
		c, _ := s.meter.Float64Counter(k)
		s.counterInstruments.Store(k, &c)
		counter = &c
	}

	(*(counter.(*instrument.Float64Counter))).Add(s.ctx, float64(val))
}

func (s *OTLPSink) AddSample(key []string, val float32) {
	s.AddSampleWithLabels(key, val, nil)
}

func (s *OTLPSink) AddSampleWithLabels(key []string, val float32, labels []metrics.Label) {
	// TODO: Handle labels and metric filtering.
	k := s.flattenKey(key)
	hist, ok := s.histogramInstruments.Load(k)
	if !ok {
		c, _ := s.meter.Float64Histogram(k)
		s.histogramInstruments.Store(k, &c)
		hist = &c
	}

	(*(hist.(*instrument.Float64Histogram))).Record(s.ctx, float64(val))
}

// Flattens the key for formatting, removes spaces
func (i *OTLPSink) flattenKey(parts []string) string {
	buf := &bytes.Buffer{}

	joined := strings.Join(parts, ".")

	spaceReplacer.WriteString(buf, joined)

	return buf.String()
}
