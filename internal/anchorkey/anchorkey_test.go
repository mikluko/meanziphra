package anchorkey

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		in, scheme, ref string
		err             bool
	}{
		{"", "", "", false},
		{"anchor.key", "file", "anchor.key", false},
		{"/abs/anchor.key", "file", "/abs/anchor.key", false},
		{"file://anchor.key", "file", "anchor.key", false},
		{"file:///abs/anchor.key", "file", "/abs/anchor.key", false},
		{"op://Private/meanziphra/key", "op", "op://Private/meanziphra/key", false},
		{"https://example.com/key", "", "", true},
	}
	for _, tt := range tests {
		got, err := ParseSource(tt.in)
		if (err != nil) != tt.err {
			t.Fatalf("%q: err = %v", tt.in, err)
		}
		if got.Scheme != tt.scheme || got.Ref != tt.ref {
			t.Errorf("%q: got %+v, want {%s %s}", tt.in, got, tt.scheme, tt.ref)
		}
	}
}

func TestLoad_FileGeneratedThenReused(t *testing.T) {
	dir := t.TempDir()
	src := Source{Scheme: "file", Ref: "anchor.key"}
	k1, created, err := Load(src, dir)
	if err != nil || !created {
		t.Fatalf("first load: created = %v, err = %v", created, err)
	}
	fi, err := os.Stat(filepath.Join(dir, "anchor.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	k2, created, err := Load(src, dir)
	if err != nil || created {
		t.Fatalf("second load: created = %v, err = %v", created, err)
	}
	if !k1.Public().(*ecdsa.PublicKey).Equal(k2.Public()) {
		t.Error("second load returned a different key")
	}
}

func TestLoad_EphemeralDiffersEachTime(t *testing.T) {
	k1, _, err := Load(Source{}, "")
	if err != nil {
		t.Fatal(err)
	}
	k2, _, err := Load(Source{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if k1.Public().(*ecdsa.PublicKey).Equal(k2.Public()) {
		t.Error("ephemeral keys repeat")
	}
}
