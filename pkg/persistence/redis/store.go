package redis

import (
	"encoding/json"
	"fmt"
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence"
	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"time"
)

type redisStore struct {
	cfg  etc.StoreConfig
	pool redis.Pool
}

func NewStore(cfg etc.StoreConfig) persistence.Store {
	return &redisStore{
		cfg: cfg,
		pool: redis.Pool{
			Dial: func() (redis.Conn, error) {
				return redis.DialURL(cfg.RedisURL)
			},
			MaxIdle:   cfg.PoolMaxIdle,
			MaxActive: cfg.PoolMaxActive,
			Wait:      true,
		},
	}
}

func (rs *redisStore) Save(scanJob job.ScanJob) error {
	conn := rs.pool.Get()
	defer rs.close(conn)

	bytes, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := rs.getKeyForScanJob(scanJob.ID)

	log.WithFields(log.Fields{
		"scan_job_id":     scanJob.ID,
		"scan_job_status": scanJob.Status.String(),
		"redis_key":       key,
	}).Debug("Saving scan job")

	_, err = conn.Do("SET", key, string(bytes))
	if err != nil {
		return xerrors.Errorf("saving scan job: %w", err)
	}

	return nil
}

func (rs *redisStore) saveWithExpire(scanJob job.ScanJob, expire time.Duration) error {
	conn := rs.pool.Get()
	defer rs.close(conn)

	bytes, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	key := rs.getKeyForScanJob(scanJob.ID)

	log.WithFields(log.Fields{
		"scan_job_id":     scanJob.ID,
		"scan_job_status": scanJob.Status.String(),
		"expire":          expire.String(),
		"redis_key":       key,
	}).Debug("Saving scan job with expire")

	err = conn.Send("MULTI")
	if err != nil {
		return err
	}
	err = conn.Send("SET", key, string(bytes))
	if err != nil {
		return err
	}
	err = conn.Send("EXPIRE", key, int(expire.Seconds()))
	if err != nil {
		return err
	}
	_, err = conn.Do("EXEC")
	if err != nil {
		return xerrors.Errorf("saving scan job: %w", err)
	}

	return nil
}

func (rs *redisStore) Get(scanJobID string) (*job.ScanJob, error) {
	conn := rs.pool.Get()
	defer rs.close(conn)

	key := rs.getKeyForScanJob(scanJobID)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}

	var scanJob job.ScanJob
	err = json.Unmarshal([]byte(value), &scanJob)
	if err != nil {
		return nil, err
	}

	return &scanJob, nil
}

func (rs *redisStore) UpdateStatus(scanJobID string, newStatus job.Status, error ...string) error {
	log.WithFields(log.Fields{
		"scan_job_id": scanJobID,
		"new_status":  newStatus.String(),
	}).Debug("Updating status for scan job")

	scanJob, err := rs.Get(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Status = newStatus
	if len(error) > 0 {
		scanJob.Error = error[0]
	}

	if newStatus == job.Finished || newStatus == job.Failed {
		return rs.saveWithExpire(*scanJob, rs.cfg.ScanJobTTL)
	}

	return rs.Save(*scanJob)
}

func (rs *redisStore) UpdateReport(scanJobID string, report harbor.ScanReport) error {
	log.WithFields(log.Fields{
		"scan_job_id": scanJobID,
	}).Debug("Updating reports for scan job")

	scanJob, err := rs.Get(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Report = report
	return rs.Save(*scanJob)
}

func (rs *redisStore) getKeyForScanJob(scanJobID string) string {
	return fmt.Sprintf("%s:scan-job:%s", rs.cfg.Namespace, scanJobID)
}

func (rs *redisStore) close(conn redis.Conn) {
	err := conn.Close()
	if err != nil {
		log.Errorf("Error while closing connection: %v", err)
	}
}
