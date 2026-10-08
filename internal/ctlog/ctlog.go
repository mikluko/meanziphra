// Package ctlog читает записи журналов Certificate Transparency по RFC 6962.
package ctlog

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
)

// Batch — сколько записей запрашивается за раз. Журналы НУЦ отвечают 403, если ответ больше 4 МБ,
// а это около 1200 записей.
const Batch = 512

// Entry — сертификат или предсертификат из журнала с цепочкой, которую журнал принял вместе с ним.
type Entry struct {
	Index int64
	Cert  []byte
	Chain [][]byte
}

// Parse разбирает запись из ответа get-entries.
func Parse(index int64, le ct.LeafEntry) (Entry, error) {
	var leaf ct.MerkleTreeLeaf
	if rest, err := tls.Unmarshal(le.LeafInput, &leaf); err != nil {
		return Entry{}, fmt.Errorf("entry %d: leaf: %w", index, err)
	} else if len(rest) > 0 {
		return Entry{}, fmt.Errorf("entry %d: leaf: %d trailing bytes", index, len(rest))
	}
	if leaf.TimestampedEntry == nil {
		return Entry{}, fmt.Errorf("entry %d: no timestamped entry", index)
	}
	e := Entry{Index: index}
	switch leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		var chain ct.CertificateChain
		if _, err := tls.Unmarshal(le.ExtraData, &chain); err != nil {
			return Entry{}, fmt.Errorf("entry %d: chain: %w", index, err)
		}
		e.Cert = leaf.TimestampedEntry.X509Entry.Data
		e.Chain = data(chain.Entries)
	case ct.PrecertLogEntryType:
		var pc ct.PrecertChainEntry
		if _, err := tls.Unmarshal(le.ExtraData, &pc); err != nil {
			return Entry{}, fmt.Errorf("entry %d: precert chain: %w", index, err)
		}
		e.Cert = pc.PreCertificate.Data
		e.Chain = data(pc.CertificateChain)
	default:
		return Entry{}, fmt.Errorf("entry %d: unsupported entry type %v", index, leaf.TimestampedEntry.EntryType)
	}
	return e, nil
}

func data(certs []ct.ASN1Cert) [][]byte {
	r := make([][]byte, len(certs))
	for i, c := range certs {
		r[i] = c.Data
	}
	return r
}

type Log struct {
	URL string
	c   *client.LogClient
}

func New(url string, hc *http.Client) (*Log, error) {
	c, err := client.New(url, hc, jsonclient.Options{UserAgent: "meanziphra"})
	if err != nil {
		return nil, err
	}
	return &Log{URL: url, c: c}, nil
}

// Size возвращает число записей в журнале по его текущему STH. Подпись STH не проверяется.
func (l *Log) Size(ctx context.Context) (int64, error) {
	sth, err := l.c.GetSTH(ctx)
	if err != nil {
		return 0, err
	}
	return int64(sth.TreeSize), nil
}

// Entries передаёт fn записи с from по to-1 по порядку. Запись, которую не удалось разобрать,
// приходит в fn с ошибкой; ошибка, которую вернул fn, прекращает чтение.
func (l *Log) Entries(ctx context.Context, from, to int64, fn func(Entry, error) error) error {
	for from < to {
		resp, err := l.c.GetRawEntries(ctx, from, min(from+Batch, to)-1)
		if err != nil {
			return err
		}
		if len(resp.Entries) == 0 {
			return errors.New("get-entries returned nothing at " + fmt.Sprint(from))
		}
		for i, le := range resp.Entries {
			if err := fn(Parse(from+int64(i), le)); err != nil {
				return err
			}
		}
		from += int64(len(resp.Entries))
	}
	return nil
}
