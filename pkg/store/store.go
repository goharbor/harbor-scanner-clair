package store

type DataStore interface {
	Set(scanID, layerName string) error
	Get(scanID string) (string, error)
}
