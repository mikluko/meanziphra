package mobileconfig

import (
	"bytes"
	"crypto/x509"
	"regexp"
	"testing"

	"howett.net/plist"

	"github.com/mikluko/meanziphra/internal/pkitest"
)

func TestBuild(t *testing.T) {
	ca := pkitest.NewCA(t)
	k := pkitest.Key(t)
	anchor := pkitest.SelfSigned(t, "Минцифры на поводке", k)
	crosses := []*x509.Certificate{ca.Root, ca.Sub}

	b, err := Build("meanziphra: banks", "desc", anchor, crosses)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("<?xml")) {
		t.Errorf("not an XML plist: %q", b[:20])
	}
	var p profile
	if _, err := plist.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p.PayloadType != "Configuration" || p.PayloadIdentifier != Identifier || p.PayloadDisplayName != "meanziphra: banks" {
		t.Errorf("profile = %+v", p)
	}
	if len(p.PayloadContent) != 3 {
		t.Fatalf("%d payloads, want 3", len(p.PayloadContent))
	}
	wantTypes := []string{"com.apple.security.root", "com.apple.security.pkcs1", "com.apple.security.pkcs1"}
	wantCerts := []*x509.Certificate{anchor, ca.Root, ca.Sub}
	uuids := map[string]bool{p.PayloadUUID: true}
	ids := map[string]bool{}
	re := regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$`)
	for i, pl := range p.PayloadContent {
		if pl.PayloadType != wantTypes[i] {
			t.Errorf("payload %d type = %s, want %s", i, pl.PayloadType, wantTypes[i])
		}
		if !bytes.Equal(pl.PayloadContent, wantCerts[i].Raw) {
			t.Errorf("payload %d carries the wrong certificate", i)
		}
		if !re.MatchString(pl.PayloadUUID) || uuids[pl.PayloadUUID] {
			t.Errorf("payload %d UUID %q is malformed or repeated", i, pl.PayloadUUID)
		}
		uuids[pl.PayloadUUID] = true
		if ids[pl.PayloadIdentifier] {
			t.Errorf("payload identifier %s repeated", pl.PayloadIdentifier)
		}
		ids[pl.PayloadIdentifier] = true
	}
}
