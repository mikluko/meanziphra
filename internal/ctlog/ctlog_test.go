package ctlog_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/mikluko/meanziphra/internal/ctlog"
	"github.com/mikluko/meanziphra/internal/ctlog/ctlogtest"
	"github.com/mikluko/meanziphra/internal/pkitest"
)

func TestEntries(t *testing.T) {
	ca := pkitest.NewCA(t)
	fake := ctlogtest.New(t, 2)
	certs := [][]byte{ca.Leaf(t, "a.test").Raw, ca.Leaf(t, "b.test").Raw, ca.Leaf(t, "c.test").Raw}
	fake.AddCert(t, certs[0], ca.Sub.Raw)
	fake.AddPrecert(t, certs[1], ca.Sub.Raw, ca.Root.Raw)
	fake.AddCert(t, certs[2])

	l, err := ctlog.New(fake.URL, fake.Client())
	if err != nil {
		t.Fatal(err)
	}
	size, err := l.Size(context.Background())
	if err != nil || size != 3 {
		t.Fatalf("Size = %d, %v", size, err)
	}
	var got []ctlog.Entry
	err = l.Entries(context.Background(), 1, size, func(e ctlog.Entry, err error) error {
		if err != nil {
			return err
		}
		got = append(got, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	for i, e := range got {
		if e.Index != int64(i+1) || !bytes.Equal(e.Cert, certs[i+1]) {
			t.Errorf("entry %d: index %d, cert mismatch %v", i, e.Index, !bytes.Equal(e.Cert, certs[i+1]))
		}
	}
	if len(got[0].Chain) != 2 || !bytes.Equal(got[0].Chain[1], ca.Root.Raw) {
		t.Errorf("precert chain = %d certs", len(got[0].Chain))
	}
	if len(got[1].Chain) != 0 {
		t.Errorf("empty chain came back with %d certs", len(got[1].Chain))
	}
}
