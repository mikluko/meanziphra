// Package jev вызывает модели System One от TypeSafe через HTTP API.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const DefaultURL = "https://api.typesafe.ai/v1/systemone"

type Client struct {
	URL    string
	APIKey string
	Model  string
	HTTP   *http.Client
	// Retries — сколько раз повторять запрос после 429, 529 и 5xx, с удвоением паузы от Backoff.
	Retries int
	Backoff time.Duration
}

type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

type Answer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    float64            `json:"confidence,omitempty"`
	Noul          float64            `json:"noul,omitempty"`
}

type Response struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
}

type request struct {
	State     any                 `json:"state"`
	Model     string              `json:"model"`
	Questions map[string]Question `json:"questions"`
}

// Ask задаёт вопросы questions про state и возвращает ответы под теми же ключами.
func (c *Client) Ask(ctx context.Context, state any, questions map[string]Question) (*Response, error) {
	body, err := json.Marshal(request{State: state, Model: c.Model, Questions: questions})
	if err != nil {
		return nil, err
	}
	wait := c.Backoff
	for attempt := 0; ; attempt++ {
		resp, retry, err := c.post(ctx, body)
		if err == nil {
			return resp, nil
		}
		if !retry || attempt >= c.Retries {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

func (c *Client) post(ctx context.Context, body []byte) (*Response, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, true, err
	}
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, retry, fmt.Errorf("typesafe: %s: %s", resp.Status, bytes.TrimSpace(b))
	}
	var r Response
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, false, fmt.Errorf("typesafe: %w", err)
	}
	return &r, false, nil
}
