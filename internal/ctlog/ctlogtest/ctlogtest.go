// Package ctlogtest поднимает для тестов журнал RFC 6962 с get-sth и get-entries.
package ctlogtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

type Log struct {
	*httptest.Server
	mu      sync.Mutex
	entries []ct.LeafEntry
	// Requests — сколько записей отдал get-entries за всё время.
	Requests int
}

// New запускает журнал; MaxBatch ограничивает, сколько записей отдаёт один get-entries.
func New(t testing.TB, maxBatch int) *Log {
	l := &Log{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/get-sth", func(w http.ResponseWriter, _ *http.Request) {
		l.mu.Lock()
		size := len(l.entries)
		l.mu.Unlock()
		sig, err := tls.Marshal(ct.DigitallySigned{
			Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
			Signature: []byte{0},
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size":           size,
			"timestamp":           1,
			"sha256_root_hash":    make([]byte, 32),
			"tree_head_signature": sig,
		})
	})
	mux.HandleFunc("/ct/v1/get-entries", func(w http.ResponseWriter, r *http.Request) {
		start, err1 := strconv.Atoi(r.URL.Query().Get("start"))
		end, err2 := strconv.Atoi(r.URL.Query().Get("end"))
		l.mu.Lock()
		defer l.mu.Unlock()
		if err1 != nil || err2 != nil || start < 0 || start > end || start >= len(l.entries) {
			http.Error(w, "bad range", http.StatusBadRequest)
			return
		}
		end = min(end, len(l.entries)-1, start+maxBatch-1)
		l.Requests += end - start + 1
		_ = json.NewEncoder(w).Encode(ct.GetEntriesResponse{Entries: l.entries[start : end+1]})
	})
	l.Server = httptest.NewServer(mux)
	t.Cleanup(l.Close)
	return l
}

// AddCert добавляет запись X509 с цепочкой chain.
func (l *Log) AddCert(t testing.TB, der []byte, chain ...[]byte) {
	t.Helper()
	l.add(t, &ct.TimestampedEntry{EntryType: ct.X509LogEntryType, X509Entry: &ct.ASN1Cert{Data: der}},
		ct.CertificateChain{Entries: asn1(chain)})
}

// AddPrecert добавляет запись Precert; der выступает предсертификатом.
func (l *Log) AddPrecert(t testing.TB, der []byte, chain ...[]byte) {
	t.Helper()
	l.add(t, &ct.TimestampedEntry{EntryType: ct.PrecertLogEntryType, PrecertEntry: &ct.PreCert{TBSCertificate: []byte{0}}},
		ct.PrecertChainEntry{PreCertificate: ct.ASN1Cert{Data: der}, CertificateChain: asn1(chain)})
}

func (l *Log) add(t testing.TB, te *ct.TimestampedEntry, extra any) {
	t.Helper()
	leaf, err := tls.Marshal(ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType, TimestampedEntry: te})
	if err != nil {
		t.Fatal(err)
	}
	ed, err := tls.Marshal(extra)
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.entries = append(l.entries, ct.LeafEntry{LeafInput: leaf, ExtraData: ed})
	l.mu.Unlock()
}

func asn1(certs [][]byte) []ct.ASN1Cert {
	r := make([]ct.ASN1Cert, len(certs))
	for i, c := range certs {
		r[i] = ct.ASN1Cert{Data: c}
	}
	return r
}
