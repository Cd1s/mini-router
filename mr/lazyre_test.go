package main

import (
	"regexp"
	"testing"
)

// Every package-level pattern compiles (they are compiled on first use, so a broken one would only
// show when that code path runs).
func TestLazyPatternsCompile(t *testing.T) {
	if len(lazyPatterns) < 40 {
		t.Fatalf("only %d lazy patterns registered", len(lazyPatterns))
	}
	for _, l := range lazyPatterns {
		if _, err := regexp.Compile(l.pat); err != nil {
			t.Errorf("%q: %v", l.pat, err)
		}
	}
}
