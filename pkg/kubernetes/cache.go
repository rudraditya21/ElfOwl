// ANCHOR: Kubernetes metadata caching - Dec 26, 2025
// Caches pod and node metadata with TTL for performance

package kubernetes

import (
	"sync"
	"time"
)

// MetadataCache caches Kubernetes metadata with TTL
type MetadataCache struct {
	mu                sync.RWMutex
	pods              map[string]*PodMetadata
	nodes             map[string]*NodeMetadata
	containerMappings map[string]string // containerID -> "namespace/podname"
	// ANCHOR: cgroupID to pod mapping cache - Fix PR-23 #3 /proc race - Mar 25, 2026
	// Maps kernel cgroup IDs (captured at event time, race-free) to "namespace/podname"
	// for direct pod resolution without relying on PID or container ID lookups.
	cgroupMappings map[uint64]string // cgroupID -> "namespace/podname"
	cgroupExpiry   map[uint64]time.Time
	expiry         map[string]time.Time
	ttlSeconds     int64
	cleanupStop    chan struct{}
	cleanupTicker  *time.Ticker
}

// NewMetadataCache creates a new metadata cache
func NewMetadataCache(ttlSeconds int64) *MetadataCache {
	cache := &MetadataCache{
		pods:              make(map[string]*PodMetadata),
		nodes:             make(map[string]*NodeMetadata),
		containerMappings: make(map[string]string),
		cgroupMappings:    make(map[uint64]string),
		cgroupExpiry:      make(map[uint64]time.Time),
		expiry:            make(map[string]time.Time),
		ttlSeconds:        ttlSeconds,
		cleanupStop:       make(chan struct{}),
	}
	cache.startCleanupLoop()
	return cache
}

func (m *MetadataCache) cleanupInterval() time.Duration {
	if m == nil || m.ttlSeconds <= 0 {
		return 10 * time.Minute
	}
	ttl := time.Duration(m.ttlSeconds) * time.Second
	interval := ttl
	if interval > 10*time.Minute {
		interval = 10 * time.Minute
	}
	if interval < time.Minute {
		interval = time.Minute
	}
	return interval
}

func (m *MetadataCache) startCleanupLoop() {
	if m == nil {
		return
	}
	m.cleanupTicker = time.NewTicker(m.cleanupInterval())
	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				m.cleanupExpired(time.Now())
			case <-m.cleanupStop:
				m.cleanupTicker.Stop()
				return
			}
		}
	}()
}

func (m *MetadataCache) cleanupExpired(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, expiry := range m.expiry {
		if now.After(expiry) {
			delete(m.expiry, key)
			delete(m.pods, key)
			delete(m.nodes, key)
			delete(m.containerMappings, key)
		}
	}

	for cgroupID, expiry := range m.cgroupExpiry {
		if now.After(expiry) {
			delete(m.cgroupExpiry, cgroupID)
			delete(m.cgroupMappings, cgroupID)
		}
	}
}

// GetPod retrieves cached pod metadata
func (m *MetadataCache) GetPod(namespace, name string) (*PodMetadata, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := namespace + "/" + name

	// Check if entry has expired
	if expiry, ok := m.expiry[key]; ok && time.Now().After(expiry) {
		// Entry expired, will be cleaned up on next set
		return nil, false
	}

	pod, found := m.pods[key]
	return pod, found
}

// SetPod stores pod metadata in cache
func (m *MetadataCache) SetPod(namespace, name string, metadata *PodMetadata) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := namespace + "/" + name
	m.pods[key] = metadata
	m.expiry[key] = time.Now().Add(time.Duration(m.ttlSeconds) * time.Second)
}

// GetNode retrieves cached node metadata
func (m *MetadataCache) GetNode(nodeName string) (*NodeMetadata, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if entry has expired
	if expiry, ok := m.expiry[nodeName]; ok && time.Now().After(expiry) {
		return nil, false
	}

	node, found := m.nodes[nodeName]
	return node, found
}

// SetNode stores node metadata in cache
func (m *MetadataCache) SetNode(nodeName string, metadata *NodeMetadata) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes[nodeName] = metadata
	m.expiry[nodeName] = time.Now().Add(time.Duration(m.ttlSeconds) * time.Second)
}

// Clear clears the entire cache
func (m *MetadataCache) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pods = make(map[string]*PodMetadata)
	m.nodes = make(map[string]*NodeMetadata)
	m.containerMappings = make(map[string]string)
	m.cgroupMappings = make(map[uint64]string)
	m.cgroupExpiry = make(map[uint64]time.Time)
	m.expiry = make(map[string]time.Time)
}

// Close stops background cleanup.
func (m *MetadataCache) Close() {
	if m == nil {
		return
	}
	select {
	case <-m.cleanupStop:
		return
	default:
		close(m.cleanupStop)
	}
}

// Size returns the current cache size
func (m *MetadataCache) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.pods) + len(m.nodes)
}

// ANCHOR: Container ID mapping cache for fast lookups - Phase 2.2, Dec 26, 2025
// Maps container IDs (from cgroups) to "namespace/podname" for quick pod resolution

// GetContainerMapping retrieves cached container ID to pod mapping
func (m *MetadataCache) GetContainerMapping(containerID string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if entry has expired
	if expiry, ok := m.expiry[containerID]; ok && time.Now().After(expiry) {
		return "", false
	}

	mapping, found := m.containerMappings[containerID]
	return mapping, found
}

// SetContainerMapping stores container ID to pod name mapping
func (m *MetadataCache) SetContainerMapping(containerID, namespacedPodName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.containerMappings[containerID] = namespacedPodName
	m.expiry[containerID] = time.Now().Add(time.Duration(m.ttlSeconds) * time.Second)
}

// GetCgroupMapping retrieves cached cgroup ID to pod mapping
func (m *MetadataCache) GetCgroupMapping(cgroupID uint64) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// ANCHOR: cgroupMapping TTL expiry - Fix PR-23 #5 stale cgroup reuse - Mar 26, 2026
	// CgroupIDs can be reused after pod restarts. Expired entries are stale and must not
	// be returned — prevents misattribution to old pods after cgroup ID reuse.
	if expiry, ok := m.cgroupExpiry[cgroupID]; ok && time.Now().After(expiry) {
		return "", false
	}

	mapping, found := m.cgroupMappings[cgroupID]
	return mapping, found
}

// SetCgroupMapping stores cgroup ID to pod name mapping
// ANCHOR: cgroupID -> pod cache population - Fix PR-23 #3 /proc race - Mar 25, 2026
// Caches cgroup IDs for direct pod resolution when /proc lookup fails.
func (m *MetadataCache) SetCgroupMapping(cgroupID uint64, namespacedPodName string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cgroupMappings[cgroupID] = namespacedPodName
	m.cgroupExpiry[cgroupID] = time.Now().Add(time.Duration(m.ttlSeconds) * time.Second)
}
