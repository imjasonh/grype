package db

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// EUVDClient is a client for interacting with the European Union Vulnerability Database (EUVD).
type EUVDClient struct {
	BaseURL string
}

// NewEUVDClient creates a new EUVDClient with the default base URL.
func NewEUVDClient() *EUVDClient {
	return &EUVDClient{
		BaseURL: "https://euvdservices.enisa.europa.eu/api",
	}
}

// Vulnerability represents a vulnerability record from the EUVD.
type Vulnerability struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Score       float64 `json:"score"`
	Date        string `json:"date"`
}

// FetchLatestVulnerabilities fetches the latest vulnerabilities from the EUVD.
func (c *EUVDClient) FetchLatestVulnerabilities() ([]Vulnerability, error) {
	url := fmt.Sprintf("%s/lastvulnerabilities", c.BaseURL)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest vulnerabilities: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var vulnerabilities []Vulnerability
	if err := json.Unmarshal(body, &vulnerabilities); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return vulnerabilities, nil
}
