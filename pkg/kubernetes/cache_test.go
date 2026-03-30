package kubernetes

import (
	"testing"
	"time"
)

func TestMetadataCacheCleanupExpiredRemovesEntries(t *testing.T) {
	cache := NewMetadataCache(300)
	defer cache.Close()

	cache.SetPod("default", "pod-a", &PodMetadata{Name: "pod-a", Namespace: "default"})
	cache.SetNode("node-a", &NodeMetadata{Name: "node-a"})
	cache.SetContainerMapping("cid-a", "default/pod-a")
	cache.SetCgroupMapping(101, "default/pod-a")

	cache.mu.Lock()
	past := time.Now().Add(-time.Minute)
	for key := range cache.expiry {
		cache.expiry[key] = past
	}
	cache.cgroupExpiry[101] = past
	cache.mu.Unlock()

	cache.cleanupExpired(time.Now())

	if _, found := cache.GetPod("default", "pod-a"); found {
		t.Fatalf("expected expired pod entry to be removed")
	}
	if _, found := cache.GetNode("node-a"); found {
		t.Fatalf("expected expired node entry to be removed")
	}
	if _, found := cache.GetContainerMapping("cid-a"); found {
		t.Fatalf("expected expired container mapping to be removed")
	}
	if _, found := cache.GetCgroupMapping(101); found {
		t.Fatalf("expected expired cgroup mapping to be removed")
	}
}

func TestMetadataCacheCleanupIntervalBounds(t *testing.T) {
	cacheShort := NewMetadataCache(30)
	defer cacheShort.Close()
	if got := cacheShort.cleanupInterval(); got != time.Minute {
		t.Fatalf("expected minimum cleanup interval 1m, got %s", got)
	}

	cacheDefault := NewMetadataCache(300)
	defer cacheDefault.Close()
	if got := cacheDefault.cleanupInterval(); got != 5*time.Minute {
		t.Fatalf("expected cleanup interval 5m for ttl=300s, got %s", got)
	}

	cacheLong := NewMetadataCache(7200)
	defer cacheLong.Close()
	if got := cacheLong.cleanupInterval(); got != 10*time.Minute {
		t.Fatalf("expected capped cleanup interval 10m, got %s", got)
	}
}
