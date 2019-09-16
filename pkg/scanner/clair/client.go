package clair

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/clair"
	"io/ioutil"
	"net/http"
	"strings"
)

// Client communicates with clair endpoint to scan image and get detailed scan result
type Client struct {
	endpoint string
	// need to customize the logger to write output to job log.
	client *http.Client
}

// NewClient creates a new instance of client, set the logger as the job's logger if it's used in a job handler.
func NewClient(endpoint string) *Client {
	return &Client{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// FIXME Allow configuring custom or self-signed certs rather that skipping verification.
				InsecureSkipVerify: true,
			},
		}},
	}
}

func (c *Client) send(req *http.Request, expectedStatus int) ([]byte, error) {
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != expectedStatus {
		return nil, fmt.Errorf("Unexpected status code: %d, text: %s", resp.StatusCode, string(b))
	}
	return b, nil
}

// ScanLayer calls Clair's API to scan a layer.
func (c *Client) ScanLayer(l clair.ClairLayer) error {
	layer := clair.ClairLayerEnvelope{
		Layer: &l,
		Error: nil,
	}
	data, err := json.Marshal(layer)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/v1/layers", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set(http.CanonicalHeaderKey("Content-Type"), "application/json")
	_, err = c.send(req, http.StatusCreated)
	if err != nil {
		return err
	}
	return nil
}

// GetResult calls Clair's API to get layers with detailed vulnerability list
func (c *Client) GetResult(layerName string) (*clair.ClairLayerEnvelope, error) {
	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/v1/layers/"+layerName+"?features&vulnerabilities", nil)
	if err != nil {
		return nil, err
	}
	b, err := c.send(req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var res clair.ClairLayerEnvelope
	err = json.Unmarshal(b, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
