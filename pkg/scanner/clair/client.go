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
type Client interface {
	ScanLayer(layer clair.Layer) error
	GetLayer(layerName string) (*clair.LayerEnvelope, error)
}

type client struct {
	endpointURL string
	// need to customize the logger to write output to job log.
	client *http.Client
}

// NewClient constructs a new client for Clair REST API pointing to the specified endpoint URL.
func NewClient(endpointURL string) Client {
	return &client{
		endpointURL: strings.TrimSuffix(endpointURL, "/"),
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// FIXME Allow configuring custom or self-signed certs rather that skipping verification.
				InsecureSkipVerify: true,
			},
		}},
	}
}

// ScanLayer calls Clair's API to scan a layer.
func (c *client) ScanLayer(layer clair.Layer) error {
	envelope := clair.LayerEnvelope{
		Layer: &layer,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpointURL+"/v1/layers", bytes.NewReader(data))
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

// GetLayer calls Clair's API to get layers with detailed vulnerability list.
func (c *client) GetLayer(layerName string) (*clair.LayerEnvelope, error) {
	url := c.endpointURL + "/v1/layers/" + layerName + "?features&vulnerabilities"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	b, err := c.send(req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var res clair.LayerEnvelope
	err = json.Unmarshal(b, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *client) send(req *http.Request, expectedStatus int) ([]byte, error) {
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
		return nil, fmt.Errorf("unexpected status code: %d, text: %s", resp.StatusCode, string(b))
	}
	return b, nil
}
