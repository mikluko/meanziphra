package domains

import (
	"slices"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		in, out string
		ok      bool
	}{
		{"Sberbank.RU", "sberbank.ru", true},
		{"*.online.sberbank.ru", "online.sberbank.ru", true},
		{"xn--80ak6aa92e.xn--p1ai", "xn--80ak6aa92e.xn--p1ai", true},
		{"sberbank.ru.", "sberbank.ru", true},
		{"localhost", "", false},
		{"10.0.0.1", "10.0.0.1", true},
		{"a..ru", "", false},
		{"a.*.ru", "", false},
		{"-bad.ru", "", false},
		{"bad-.ru", "", false},
		{"under_score.ru", "", false},
		{"пример.рф", "", false},
	}
	for _, tt := range tests {
		got, ok := Normalize(tt.in)
		if ok != tt.ok || got != tt.out {
			t.Errorf("Normalize(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.out, tt.ok)
		}
	}
}

func TestTLD(t *testing.T) {
	if got := TLD("online.sberbank.ru"); got != "ru" {
		t.Errorf("TLD = %q", got)
	}
}

func TestMinimize(t *testing.T) {
	got := Minimize([]string{"online.sberbank.ru", "sberbank.ru", "a.b.c.tbank.ru", "tbank.ru", "notsberbank.ru", "sberbank.ru"})
	want := []string{"notsberbank.ru", "sberbank.ru", "tbank.ru"}
	if !slices.Equal(got, want) {
		t.Errorf("Minimize = %v, want %v", got, want)
	}
}

func TestZones(t *testing.T) {
	if got, want := Zones([]string{"b.ru", "a.su", "c.ru", "xn--80ak6aa92e.xn--p1ai"}), []string{"ru", "su", "xn--p1ai"}; !slices.Equal(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}
}
