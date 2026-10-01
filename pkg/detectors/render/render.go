package render

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const validateURL = "https://api.render.com/hooks/secretscans/th"

var (
	_             detectors.Detector = (*Scanner)(nil)
	keyPat                           = regexp.MustCompile(`\b(rnd_[0-9a-zA-Z_]{28})\b`)
	defaultClient                    = common.SaneHttpClient()
)

type Scanner struct {
	client *http.Client
}

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"rnd_"}
}

// FromData will find and optionally verify Render secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detector_typepb.DetectorType_Render,
			Raw:          []byte(match),
			SecretParts:  map[string]string{"key": match},
		}
		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}
			isVerified, verificationErr := sendRequest(ctx, client, validateURL, match)
			s1.Verified = isVerified
			s1.SetVerificationError(verificationErr, match)
		}
		results = append(results, s1)
	}
	return
}

func (s Scanner) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Render
}

func (s Scanner) Description() string {
	return "Render is an infrastructure provider that provides tools and services to help developers ship faster. Render API keys can be used to access these services."
}

func sendRequest(ctx context.Context, client *http.Client, endpoint, token string) (bool, error) {
	body, err := json.Marshal(struct {
		Kind  string `json:"kind"`
		Token string `json:"token"`
	}{Kind: "api_key", Token: token})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusCreated:
		return true, nil
	case http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("[Render] Validation request returned HTTP %d", res.StatusCode)
	}
}
