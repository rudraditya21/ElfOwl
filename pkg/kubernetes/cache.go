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
	expiry            map[string]time.Time
	ttlSeconds        int64
}

// NewMetadataCache creates a new metadata cache
func NewMetadataCache(ttlSeconds int64) *MetadataCache {
	return &MetadataCache{
		pods:              make(map[string]*PodMetadata),
		nodes:             make(map[string]*NodeMetadata),
		containerMappings: make(map[string]string),
		expiry:            make(map[string]time.Time),
		ttlSeconds:        ttlSeconds,
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
	m.expiry = make(map[string]time.Time)
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
