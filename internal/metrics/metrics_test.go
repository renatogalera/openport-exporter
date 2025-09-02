package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestUpdateMetrics(t *testing.T) {
    mc := NewMetricsCollector()

    // targetKey format: target_portRange_proto
    target := "192.168.1.0/24"
    portRange := "80,443"
    proto := "tcp"
    targetKey := target + "_" + portRange + "_" + proto

    // First run: two open ports in aggregate
    newResults := map[string]struct{}{
        "192.168.1.10:80/tcp":  {},
        "192.168.1.20:443/tcp": {},
    }
    mc.UpdateMetrics(targetKey, newResults)
    assert.Equal(t, float64(2), testutil.ToFloat64(mc.scanTargetOpenPortsTotal.WithLabelValues(target, portRange, proto)))

    // Second run: only one open port remains
    newResults = map[string]struct{}{
        "192.168.1.10:80/tcp": {},
    }
    mc.UpdateMetrics(targetKey, newResults)
    assert.Equal(t, float64(1), testutil.ToFloat64(mc.scanTargetOpenPortsTotal.WithLabelValues(target, portRange, proto)))
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
