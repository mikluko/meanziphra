package jev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAsk(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(529)
			return
		}
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Model != "jev-1.13.0" || req.Questions["category"].Type != "choice" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		_, _ = w.Write([]byte(`{"model":"jev-1.13.0","answers":{"category":{"type":"choice","choice":"banks","confidence":0.9,"probabilities":{"banks":0.95,"other":0.05}}},"usage":{}}`))
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL, APIKey: "k", Model: "jev-1.13.0", HTTP: srv.Client(), Retries: 2}
	resp, err := c.Ask(context.Background(), map[string]string{"org": "Sberbank"}, map[string]Question{
		"category": {Type: "choice", Instructions: "?", Criteria: map[string]string{"banks": "b", "other": "o"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := resp.Answers["category"]
	if a.Choice != "banks" || a.Confidence != 0.9 || a.Probabilities["banks"] != 0.95 || calls != 2 {
		t.Errorf("answer %+v after %d calls", a, calls)
	}
}

func TestAsk_NoRetryOnClientError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, HTTP: srv.Client(), Retries: 3}
	if _, err := c.Ask(context.Background(), "s", nil); err == nil || calls != 1 {
		t.Errorf("err = %v after %d calls, want one failed call", err, calls)
	}
}
