package clair

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	_ "github.com/lib/pq"
	"github.com/xo/dburl"
)

const (
	updaterLast = "updater/last"
)

// Client communicates with clair endpoint to scan image and get detailed scan result
type Client interface {
	ScanLayer(layer Layer) error
	GetLayer(layerName string) (*LayerEnvelope, error)
	GetVulnerabilityDatabaseUpdatedAt() (*time.Time, error)
}

type client struct {
	db          *sql.DB
	endpointURL string
	// need to customize the logger to write output to job log.
	client *http.Client
}

// NewClient constructs a new client for Clair REST API pointing to the specified endpoint URL.
func NewClient(tlsConfig etc.TLSConfig, cfg etc.ClairConfig) (Client, error) {
	var db *sql.DB
	if cfg.DatabaseURL != "" {
		// GetVulnerabilityDatabaseUpdatedAt feature enabled when Clair database url is not empty,
		// error will be returned when connect Clair database failed.
		var err error
		db, err = dburl.Open(cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
	}

	return &client{
		db:          db,
		endpointURL: strings.TrimSuffix(cfg.URL, "/"),
		client: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
				RootCAs:            tlsConfig.RootCAs,
			},
		}},
	}, nil
}

// ScanLayer calls Clair's API to scan a layer.
func (c *client) ScanLayer(layer Layer) error {
	envelope := LayerEnvelope{
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
func (c *client) GetLayer(layerName string) (*LayerEnvelope, error) {
	url := c.endpointURL + "/v1/layers/" + layerName + "?features&vulnerabilities"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	b, err := c.send(req, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var res LayerEnvelope
	err = json.Unmarshal(b, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *client) GetVulnerabilityDatabaseUpdatedAt() (*time.Time, error) {
	if c.db == nil {
		// feature not enabled
		return nil, nil
	}

	rows, err := c.db.Query("SELECT value from keyvalue where key = $1", updaterLast)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	values := make([]string, 0)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			log.Fatal(err)
		}
		values = append(values, value)
	}

	if len(values) == 0 {
		// updater not finished
		return nil, nil
	} else if len(values) > 1 {
		return nil, fmt.Errorf("multiple entries for %s in Clair DB", updaterLast)
	}

	overallLastUpdate, err := strconv.ParseInt(values[0], 0, 64)
	if err != nil {
		return nil, err
	}

	updateAt := time.Unix(overallLastUpdate, 0)

	return &updateAt, nil
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
