package classify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/mikluko/meanziphra/internal/ctstate"
	"github.com/mikluko/meanziphra/internal/jev"
)

type fakeClassifier struct {
	calls atomic.Int32
	fail  string
}

func (f *fakeClassifier) Classify(_ context.Context, s Subject) (Entry, error) {
	f.calls.Add(1)
	if s.Org == f.fail {
		return Entry{}, errors.New("boom")
	}
	return Entry{Category: "c-" + s.Org, Org: s.Org}, nil
}

func TestKey(t *testing.T) {
	if got := Key("a.ru", ctstate.Owner{OGRN: "1"}); got != "ogrn:1" {
		t.Errorf("Key = %s", got)
	}
	if got := Key("a.ru", ctstate.Owner{Org: "A"}); got != "name:a.ru" {
		t.Errorf("Key = %s", got)
	}
}

func TestFill_OnlyMissing(t *testing.T) {
	c := &Cache{Entries: map[string]Entry{"k1": {Category: "kept"}}}
	subjects := map[string]Subject{"k1": {Org: "A"}, "k2": {Org: "B"}, "k3": {Org: "C"}}
	cl := &fakeClassifier{}
	n, err := Fill(context.Background(), c, subjects, cl, 2)
	if err != nil || n != 2 || cl.calls.Load() != 2 {
		t.Fatalf("n = %d, calls = %d, err = %v", n, cl.calls.Load(), err)
	}
	if c.Entries["k1"].Category != "kept" || c.Entries["k3"].Category != "c-C" {
		t.Errorf("entries = %+v", c.Entries)
	}
}

func TestFill_StopsOnError(t *testing.T) {
	c := &Cache{Entries: map[string]Entry{}}
	_, err := Fill(context.Background(), c, map[string]Subject{"k1": {Org: "bad"}, "k2": {Org: "B"}}, &fakeClassifier{fail: "bad"}, 1)
	if err == nil {
		t.Fatal("error swallowed")
	}
	if _, ok := c.Entries["k1"]; ok {
		t.Error("failed subject got an entry")
	}
}

func TestCache_FingerprintAndRetain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	c, err := Load(path, "fp1")
	if err != nil {
		t.Fatal(err)
	}
	c.Entries["k1"] = Entry{Category: "banks"}
	c.Entries["k2"] = Entry{Category: "gov"}
	c.Retain(map[string]Subject{"k1": {}})
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	same, err := Load(path, "fp1")
	if err != nil {
		t.Fatal(err)
	}
	if len(same.Entries) != 1 || same.Entries["k1"].Category != "banks" {
		t.Errorf("reloaded %+v", same.Entries)
	}
	other, err := Load(path, "fp2")
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Entries) != 0 || other.Fingerprint != "fp2" {
		t.Errorf("changed fingerprint kept %+v", other)
	}
}

func TestJev(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"model":"m","answers":{"category":{"type":"choice","choice":"banks","confidence":0.41234,"probabilities":{"banks":0.6,"gov":0.4}}}}`))
	}))
	defer srv.Close()
	j := &Jev{
		Client:        &jev.Client{URL: srv.URL, HTTP: srv.Client()},
		Criteria:      map[string]string{"banks": "b", "gov": "g"},
		MinConfidence: 0.5,
	}
	e, err := j.Classify(context.Background(), Subject{Org: "Sber"})
	if err != nil {
		t.Fatal(err)
	}
	if e != (Entry{Category: "banks", Confidence: 0.412, Review: true, Org: "Sber"}) {
		t.Errorf("entry = %+v", e)
	}
	j.Criteria = map[string]string{"gov": "g"}
	if _, err := j.Classify(context.Background(), Subject{}); err == nil {
		t.Error("accepted an answer outside the categories")
	}
}
