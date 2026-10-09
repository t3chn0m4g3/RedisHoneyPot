package honeypot

import (
	"strings"
	"testing"
)

func TestStringMatchRedisSemantics(t *testing.T) {
	cases := []struct {
		pattern, str string
		nocase, want bool
	}{
		{"*", "a/b", false, true},
		{"sess*", "sess/abc", false, true},
		{"h?llo", "h/llo", false, true},
		{"h[ae]llo", "hallo", false, true},
		{"h[ae]llo", "hillo", false, false},
		{"h[^e]llo", "hallo", false, true},
		{"h[^e]llo", "hello", false, false},
		{"h[a-b]llo", "hbllo", false, true},
		{"h[b-a]llo", "hallo", false, true},
		{"h\\*llo", "h*llo", false, true},
		{"h\\*llo", "hallo", false, false},
		{"DIR", "dir", true, true},
		{"DIR", "dir", false, false},
		{"*max*", "maxmemory-policy", false, true},
		{"a*b*", "ab", false, true},
		{"abc", "ab", false, false},
		{"[", "[", false, false}, // unterminated class never matches in Redis
	}
	for _, tc := range cases {
		if got := stringMatch(tc.pattern, tc.str, tc.nocase); got != tc.want {
			t.Errorf("stringMatch(%q, %q, %t) = %t, want %t", tc.pattern, tc.str, tc.nocase, got, tc.want)
		}
	}
}

func TestStringMatchAbusivePatternTerminates(t *testing.T) {
	pattern := strings.Repeat("a*", 64) + "b"
	if stringMatch(pattern, strings.Repeat("a", 4096), false) {
		t.Fatal("abusive pattern unexpectedly matched")
	}
}

func TestKeysMatchesSlashes(t *testing.T) {
	store := NewStore()
	store.Set(0, "sess/abc", "1")
	store.Set(0, "other", "1")
	if got := store.Keys(0, "sess*"); len(got) != 1 || got[0] != "sess/abc" {
		t.Fatalf("KEYS sess* = %v, want [sess/abc]", got)
	}
}
