package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestUpdateMetrics(t *testing.T) {
	// Initialize MetricsCollector
	mc := NewMetricsCollector()

	// Initializing state
	targetKey := "192.168.1.1_80"
	newResults := map[string]struct{}{
		"192.168.1.1:80":  {},
		"192.168.1.1:443": {},
	}

	// Update metrics with new open ports
	mc.UpdateMetrics(targetKey, newResults)

	// Check if metrics were updated correctly
	ip := "192.168.1.1"
	port80 := "80"
	port443 := "443"
	assert.Equal(t, float64(1), testutil.ToFloat64(mc.openPorts.WithLabelValues(ip, port80, "tcp")))
	assert.Equal(t, float64(1), testutil.ToFloat64(mc.openPorts.WithLabelValues(ip, port443, "tcp")))

	// Update with closed ports (443 removed)
	newResults = map[string]struct{}{
		"192.168.1.1:80": {},
	}
	mc.UpdateMetrics(targetKey, newResults)

	// Verify that port 443 is closed
	assert.Equal(t, float64(0), testutil.ToFloat64(mc.openPorts.WithLabelValues(ip, port443, "tcp")))
}

func TestCanScan(t *testing.T) {
	mc := NewMetricsCollector()
	targetKey := "192.168.1.1_80"
	scanInterval := 10 * time.Second

	// Register a new scan
	mc.RegisterScan(targetKey)

	// Check that a new scan cannot be performed immediately
	canScan := mc.CanScan(targetKey, scanInterval)
	assert.False(t, canScan, "A new scan should not be allowed right after registering a scan")

	// Simulate time passing to allow a new scan by adjusting LastScan
	if val, ok := mc.scannedTargets.Load(targetKey); ok {
		if si, ok := val.(*ScanInfo); ok {
			si.LastScan = si.LastScan.Add(-11 * time.Second)
			mc.scannedTargets.Store(targetKey, si)
		}
	}

	// Check that a new scan can be performed after enough time
	canScan = mc.CanScan(targetKey, scanInterval)
	assert.True(t, canScan, "A new scan should be allowed after the scan interval")
}

func TestRegisterScan(t *testing.T) {
	mc := NewMetricsCollector()
	targetKey := "192.168.1.1_80"

	// Register a new scan
	mc.RegisterScan(targetKey)

	// Check that the scan was registered correctly
	scanInfo, exists := mc.scannedTargets.Load(targetKey)
	assert.True(t, exists, "The target should have been registered")
	assert.NotNil(t, scanInfo, "ScanInfo should not be nil")
	if si, ok := scanInfo.(*ScanInfo); ok {
		assert.Empty(t, si.Ports, "Initially, no ports should be registered for the scan")
	} else {
		t.Error("scanInfo is not of type *ScanInfo")
	}
}

func TestObserveScanDuration(t *testing.T) {
	mc := NewMetricsCollector()
	target := "192.168.1.1"
	portRange := "80-443"
	protocol := "tcp"
	duration := 1.23

	// Observe the scan duration
	mc.ObserveScanDuration(target, portRange, protocol, duration)

	// Check if the scan duration metric was updated correctly
	assert.Equal(t, duration, testutil.ToFloat64(mc.scanDuration.WithLabelValues(target, portRange, protocol)))
}

func TestUpdateTaskQueueSize(t *testing.T) {
	mc := NewMetricsCollector()
	queueSize := 5

	// Update the task queue size metric
	mc.UpdateTaskQueueSize(queueSize)

	// Check if the task queue size metric was updated correctly
	assert.Equal(t, float64(queueSize), testutil.ToFloat64(mc.taskQueueSizeMetric))
}
