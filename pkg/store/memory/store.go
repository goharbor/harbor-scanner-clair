package memory

import (
	"errors"
	"github.com/goharbor/harbor-scanner-clair/pkg/store"
)

type memoryStore struct {
	data map[string]string
}

func NewDataStore() store.DataStore {
	return &memoryStore{
		data: make(map[string]string),
	}
}

func (s *memoryStore) Set(scanID, layerName string) error {
	s.data[scanID] = layerName
	return nil
}

func (s *memoryStore) Get(scanID string) (string, error) {
	if layerName, ok := s.data[scanID]; ok {
		return layerName, nil
	}
	return "", errors.New("not found")
}
