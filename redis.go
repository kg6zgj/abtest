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
	once.Do(func() {
		conn, err := redis.Dial("tcp", addr, redis.DialPassword(password))
		if err != nil {
			logger.Error("redis init error", "addr", addr, "password", password, "error", err)
			panic(err)
		}
		redisInst = conn
	})
}

func GetRedisInst() redis.Conn {
	return redisInst
}
