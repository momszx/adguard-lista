package main

import (
	"reflect"
	"testing"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		in     string
		domain string
		allow  bool
		ok     bool
	}{
		{"||Ads.Example.com^", "ads.example.com", false, true},
		{"@@||ok.example.com^", "ok.example.com", true, true},
		{"0.0.0.0 tracker.example.net", "tracker.example.net", false, true},
		{"127.0.0.1 localhost", "", false, false},
		{"phish.example.org # comment", "phish.example.org", false, true},
		{"||example.com^$important", "", false, false},
		{"||*.example.com^", "", false, false},
		{"/regex/", "", false, false},
		{"! comment", "", false, false},
		{"192.168.0.1", "", false, false},
		{"localhost", "", false, false},
	}
	for _, c := range cases {
		d, a, ok := parseLine(c.in)
		if d != c.domain || a != c.allow || ok != c.ok {
			t.Errorf("parseLine(%q) = %q,%v,%v want %q,%v,%v", c.in, d, a, ok, c.domain, c.allow, c.ok)
		}
	}
}

func TestMerge(t *testing.T) {
	block := map[string]bool{
		"example.com":      true,
		"sub.example.com":  true, // covered by example.com
		"a.b.other.org":    true,
		"allowed.net":      true, // allowed exactly
		"x.allowed.net":    true, // under an allowed domain
		"keep.allowed.org": true,
	}
	allow := map[string]bool{"allowed.net": true}
	got := merge(block, allow)
	want := []string{"a.b.other.org", "example.com", "keep.allowed.org"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merge = %v want %v", got, want)
	}
}
