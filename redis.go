package abtest

import (
	"sync"

	"github.com/gomodule/redigo/redis"
)

var (
	redisInst redis.Conn
	once      sync.Once
)

func initRedis(addr string, password string) {
	logger := NewLogger("INFO")
	once.Do(func() {
		conn, err := redis.Dial("tcp", addr)
		if err != nil {
			logger.Error("redis dial failed", "error", err)
			panic(err)
		}

		if password != "" {
			_, err := redis.String(conn.Do("AUTH", password))
			if err != nil && err.Error() != "OK" {
				logger.Error("redis auth failed", "error", err)
				panic(err)
			}
		}

		redisInst = conn
	})
}

func GetRedisInst() redis.Conn {
	return redisInst
}
