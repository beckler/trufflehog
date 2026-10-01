package render

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestRenderPattern(t *testing.T) {
	key := "rnd_" + strings.Repeat("a", 28)
	scanner := Scanner{}
	filter := ahocorasick.NewAhoCorasickCore([]detectors.Detector{scanner})
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"API key", "RENDER_API_KEY=" + key, key},
		{"embedded in prose", "Render key: " + key + ".", key},
		{"too short", "RENDER_API_KEY=rnd_" + strings.Repeat("a", 27), ""},
		{"too long", "RENDER_API_KEY=" + key + "a", ""},
		{"wrong prefix", "RENDER_API_KEY=abc_" + strings.Repeat("a", 28), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.want != "" {
				require.NotEmpty(t, filter.FindDetectorMatches([]byte(tt.input)))
			}
			results, err := scanner.FromData(context.Background(), false, []byte(tt.input))
			require.NoError(t, err)
			if tt.want == "" {
				require.Empty(t, results)
				return
			}
			require.Len(t, results, 1)
			require.Equal(t, tt.want, string(results[0].Raw))
			require.Equal(t, map[string]string{"key": tt.want}, results[0].SecretParts)
		})
	}
}

func TestRenderVerification(t *testing.T) {
	key := "rnd_" + strings.Repeat("a", 28)
	for _, tt := range []struct {
		name     string
		status   int
		verified bool
		hasError bool
	}{
		{"verified", http.StatusCreated, true, false},
		{"rejected", http.StatusForbidden, false, false},
		{"unexpected response", http.StatusNotFound, false, true},
		{"rate limited", http.StatusTooManyRequests, false, true},
		{"server unavailable", http.StatusServiceUnavailable, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scanner := Scanner{client: common.ConstantResponseHttpClient(tt.status, "")}
			results, err := scanner.FromData(context.Background(), true, []byte(key))
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Equal(t, tt.verified, results[0].Verified)
			require.Equal(t, tt.hasError, results[0].VerificationError() != nil)
			require.Equal(t, map[string]string{"key": key}, results[0].SecretParts)
		})
	}
}

func TestRenderVerificationTimeout(t *testing.T) {
	key := "rnd_" + strings.Repeat("a", 28)
	client := &http.Client{Transport: common.FakeTransport{CreateResponse: func(*http.Request) (*http.Response, error) {
		return nil, context.DeadlineExceeded
	}}}
	results, err := (Scanner{client: client}).FromData(context.Background(), true, []byte(key))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].Verified)
	require.ErrorContains(t, results[0].VerificationError(), context.DeadlineExceeded.Error())
	require.Equal(t, map[string]string{"key": key}, results[0].SecretParts)
}

func TestRenderVerificationRequest(t *testing.T) {
	key := "rnd_" + strings.Repeat("a", 28)
	client := &http.Client{Transport: common.FakeTransport{
		CreateResponse: func(req *http.Request) (*http.Response, error) {
			require.Equal(t, http.MethodPost, req.Method)
			require.Equal(t, "https://api.render.com/hooks/secretscans/th", req.URL.String())
			require.Empty(t, req.Header.Get("Authorization"))
			require.Equal(t, "application/json", req.Header.Get("Content-Type"))
			var body map[string]string
			require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
			require.Equal(t, map[string]string{"kind": "api_key", "token": key}, body)
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(""))}, nil
		},
	}}
	results, err := (Scanner{client: client}).FromData(context.Background(), true, []byte(key))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.True(t, results[0].Verified)
}

func TestRenderNoVerificationWhenDisabled(t *testing.T) {
	key := "rnd_" + strings.Repeat("a", 28)
	calls := 0
	client := &http.Client{Transport: common.FakeTransport{CreateResponse: func(*http.Request) (*http.Response, error) {
		calls++
		return nil, context.DeadlineExceeded
	}}}
	results, err := (Scanner{client: client}).FromData(context.Background(), false, []byte(key+" "+key))
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].Verified)
	require.Equal(t, map[string]string{"key": key}, results[0].SecretParts)
	require.Zero(t, calls)
}
