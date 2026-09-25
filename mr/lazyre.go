package main

// Package-level patterns compile on first use (Cd1s/mini-router#8). mr starts once per CGI request
// and per hook, and a call uses few of the ~50 patterns: compiling all of them at start cost ~2.5 MB
// and ~3 ms of init on x86 (several times that on the router's A53) every time. lazyPatterns keeps
// them all so a test can check that every one compiles.

import (
	"regexp"
	"sync"
)

type lazyRE struct {
	pat  string
	once sync.Once
	re   *regexp.Regexp
}

var lazyPatterns []*lazyRE

func lazyRegexp(pat string) *lazyRE {
	l := &lazyRE{pat: pat}
	lazyPatterns = append(lazyPatterns, l)
	return l
}

func (l *lazyRE) get() *regexp.Regexp {
	l.once.Do(func() { l.re = regexp.MustCompile(l.pat) })
	return l.re
}

func (l *lazyRE) MatchString(s string) bool            { return l.get().MatchString(s) }
func (l *lazyRE) FindString(s string) string           { return l.get().FindString(s) }
func (l *lazyRE) FindStringSubmatch(s string) []string { return l.get().FindStringSubmatch(s) }
func (l *lazyRE) FindSubmatch(b []byte) [][]byte       { return l.get().FindSubmatch(b) }
func (l *lazyRE) String() string                       { return l.pat }

func (l *lazyRE) FindAllString(s string, n int) []string { return l.get().FindAllString(s, n) }

func (l *lazyRE) FindAllStringSubmatch(s string, n int) [][]string {
	return l.get().FindAllStringSubmatch(s, n)
}

func (l *lazyRE) ReplaceAllString(s, repl string) string { return l.get().ReplaceAllString(s, repl) }

func (l *lazyRE) ReplaceAllStringFunc(s string, f func(string) string) string {
	return l.get().ReplaceAllStringFunc(s, f)
}
