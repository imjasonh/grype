package db

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEUVDClient_FetchLatestVulnerabilities(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/api/lastvulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"id": "example-vuln-1", "description": "Example vulnerability 1", "score": 7.5, "date": "2025-05-01"},
			{"id": "example-vuln-2", "description": "Example vulnerability 2", "score": 9.0, "date": "2025-05-02"}
		]`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := &EUVDClient{BaseURL: server.URL + "/api"}

	vulnerabilities, err := client.FetchLatestVulnerabilities()
	require.NoError(t, err)
	assert.Len(t, vulnerabilities, 2)
	assert.Equal(t, "example-vuln-1", vulnerabilities[0].ID)
	assert.Equal(t, "Example vulnerability 1", vulnerabilities[0].Description)
	assert.Equal(t, 7.5, vulnerabilities[0].Score)
	assert.Equal(t, "2025-05-01", vulnerabilities[0].Date)
}

func TestEUVDClient_FetchLatestVulnerabilities_ErrorResponse(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/api/lastvulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := &EUVDClient{BaseURL: server.URL + "/api"}

	vulnerabilities, err := client.FetchLatestVulnerabilities()
	assert.Error(t, err)
	assert.Nil(t, vulnerabilities)
}

func TestEUVDClient_FetchLatestVulnerabilities_InvalidJSON(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/api/lastvulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`invalid-json`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := &EUVDClient{BaseURL: server.URL + "/api"}

	vulnerabilities, err := client.FetchLatestVulnerabilities()
	assert.Error(t, err)
	assert.Nil(t, vulnerabilities)
}

func TestEUVDClient_FetchLatestVulnerabilities_EmptyResponse(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/api/lastvulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	client := &EUVDClient{BaseURL: server.URL + "/api"}

	vulnerabilities, err := client.FetchLatestVulnerabilities()
	require.NoError(t, err)
	assert.Empty(t, vulnerabilities)
}
