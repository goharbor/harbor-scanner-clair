package redisx

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/goharbor/harbor-scanner-clair/pkg/etc"

	"github.com/FZambia/sentinel"
	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

// NewPool constructs a redis.Pool for the given RedisPool config params.
//
// The currently supported Redis URL schemas correspond to a Redis server
// run in standalone and Sentinel modes:
// - redis://user:password@standalone_host:port/db-number
// - redis+sentinel://user:password@sentinel_host1:port1,sentinel_host2:port2/monitor-name/db-number
func NewPool(config etc.RedisPool) (*redis.Pool, error) {
	configURL, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid redis URL: %s", err)
	}

	switch configURL.Scheme {
	case "redis":
		return newInstancePool(config), nil
	case "redis+sentinel":
		return newSentinelPool(configURL, config)
	default:
		return nil, fmt.Errorf("invalid redis URL scheme: %s", configURL.Scheme)
	}
}

// redis://user:password@standalone_host:port/db-number
func newInstancePool(config etc.RedisPool) *redis.Pool {
	log.Trace("Constructing connection pool for Redis instance")
	return &redis.Pool{
		Dial: func() (redis.Conn, error) {
			log.WithField("url", config.URL).Trace("Connecting to Redis")
			return redis.DialURL(config.URL)
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			log.Trace("Testing connection to Redis on borrow")
			_, err := c.Do("PING")
			return err
		},
		MaxIdle:     config.MaxIdle,
		MaxActive:   config.MaxActive,
		IdleTimeout: config.IdleTimeout,
		Wait:        true,
	}
}

// redis+sentinel://user:password@sentinel_host1:port1,sentinel_host2:port2/monitor-name/db-number
func newSentinelPool(configURL *url.URL, config etc.RedisPool) (pool *redis.Pool, err error) {
	log.Trace("Constructing connection pool for Redis Sentinel")
	sentinelURL, err := ParseSentinelURL(configURL)
	if err != nil {
		return
	}

	var commonOpts []redis.DialOption
	if config.ConnectionTimeout > 0 {
		commonOpts = append(commonOpts, redis.DialConnectTimeout(config.ConnectionTimeout))
	}
	if config.ReadTimeout > 0 {
		commonOpts = append(commonOpts, redis.DialReadTimeout(config.ReadTimeout))
	}
	if config.WriteTimeout > 0 {
		commonOpts = append(commonOpts, redis.DialWriteTimeout(config.WriteTimeout))
	}

	sentinelOpts := commonOpts

	sntnl := &sentinel.Sentinel{
		Addrs:      sentinelURL.Addrs,
		MasterName: sentinelURL.MonitorName,
		Dial: func(addr string) (redis.Conn, error) {
			log.WithField("addr", addr).Trace("Connecting to Redis sentinel")
			return redis.Dial("tcp", addr, sentinelOpts...)
		},
	}

	redisOpts := commonOpts

	redisOpts = append(redisOpts, redis.DialDatabase(sentinelURL.Database))
	redisOpts = append(redisOpts, redis.DialPassword(sentinelURL.Password))

	pool = &redis.Pool{
		Dial: func() (conn redis.Conn, err error) {
			masterAddr, err := sntnl.MasterAddr()
			if err != nil {
				return
			}
			log.WithField("addr", masterAddr).Trace("Connecting to Redis master")
			return redis.Dial("tcp", masterAddr, redisOpts...)
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			log.Trace("Testing connection to Redis master on borrow")
			if !sentinel.TestRole(c, "master") {
				return errors.New("role check failed")
			}
			return nil
		},
		MaxIdle:     config.MaxIdle,
		MaxActive:   config.MaxActive,
		IdleTimeout: config.IdleTimeout,
		Wait:        true,
	}
	return
}

type SentinelURL struct {
	Password    string
	Addrs       []string
	MonitorName string
	Database    int
}

func ParseSentinelURL(configURL *url.URL) (sentinelURL SentinelURL, err error) {
	ps := strings.Split(configURL.Path, "/")
	if len(ps) < 2 {
		err = fmt.Errorf("invalid redis sentinel URL: no master name")
		return
	}

	if user := configURL.User; user != nil {
		if password, set := user.Password(); set {
			sentinelURL.Password = password
		}
	}

	sentinelURL.Addrs = strings.Split(configURL.Host, ",")
	sentinelURL.MonitorName = ps[1]

	if len(ps) > 2 {
		sentinelURL.Database, err = strconv.Atoi(ps[2])
		if err != nil {
			err = fmt.Errorf("invalid redis sentinel URL: invalid database number: %s", ps[2])
			return
		}
	}

	return
}
