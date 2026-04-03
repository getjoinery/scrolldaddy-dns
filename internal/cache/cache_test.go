package cache

import (
	"testing"
)

func TestIsDomainInSet_ExactMatch(t *testing.T) {
	set := map[string]bool{"ads.example.com": true}
	if !IsDomainInSet("ads.example.com", set) {
		t.Error("exact match should be blocked")
	}
}

func TestIsDomainInSet_ParentMatch(t *testing.T) {
	set := map[string]bool{"ads.example.com": true}
	if !IsDomainInSet("tracker.ads.example.com", set) {
		t.Error("subdomain of blocked domain should be blocked")
	}
}

func TestIsDomainInSet_TLDNotMatched(t *testing.T) {
	set := map[string]bool{"com": true}
	if IsDomainInSet("example.com", set) {
		t.Error("TLD-only entry should not block example.com")
	}
}

func TestIsDomainInSet_NoFalsePositive(t *testing.T) {
	set := map[string]bool{"example.com": true}
	if IsDomainInSet("notexample.com", set) {
		t.Error("example.com in blocklist should not block notexample.com")
	}
	if IsDomainInSet("otherexample.com", set) {
		t.Error("example.com in blocklist should not block otherexample.com")
	}
}

func TestIsDomainInSet_DeepSubdomain(t *testing.T) {
	set := map[string]bool{"example.com": true}
	if !IsDomainInSet("a.b.c.example.com", set) {
		t.Error("deep subdomain of blocked domain should be blocked")
	}
}

func TestIsDomainInSet_NotBlocked(t *testing.T) {
	set := map[string]bool{"blocked.com": true}
	if IsDomainInSet("google.com", set) {
		t.Error("unrelated domain should not be blocked")
	}
}

func TestIsDomainInSet_EmptySet(t *testing.T) {
	set := map[string]bool{}
	if IsDomainInSet("anything.com", set) {
		t.Error("empty set should not block anything")
	}
}
