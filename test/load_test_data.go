package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

var configFile = flag.String("c", "", "config file")

type Rule struct {
	ServiceName string `yaml:"serviceName"`
	Name        string `yaml:"name"`
	Enable      bool   `yaml:"enable"`
	Desc        string `yaml:"desc"`
	Host        string `yaml:"host"`
	Priority    int    `yaml:"priority"`
	Strategy    string `yaml:"strategy"`
	List        string `yaml:"list"`
	Percent     int    `yaml:"percent"`
	Version     string `yaml:"version"`
	UrlMatchKey string `yaml:"urlMatchKey"`
}
type Config struct {
	RedisAddr     string `yaml:"redisAddr"`
	RedisPassword string `yaml:"redisPassword"`
	Rules         []Rule `yaml:"rules"`
}

func main() {
	flag.Parse()
	log.Println("config file ", *configFile)
	data, err := os.ReadFile(*configFile)
	if err != nil {
		log.Println("read config error", err)
		return
	}
	cfg := Config{}
	//log.Println("config data is ", string(data))
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		log.Println("unmarshal config error ", err)
		return
	}

	v, err := json.Marshal(cfg)
	log.Println(string(v), err)

	rdb, err := redis.Dial("tcp", cfg.RedisAddr, redis.DialPassword(cfg.RedisPassword))
	if err != nil {
		log.Println("init redis error", err)
		return
	}

	for _, rule := range cfg.Rules {
		log.Println("insert rule ", rule.Name)
		ruleKey := fmt.Sprintf("abtest:%s", rule.Name)
		rdb.Do("LPUSH", "abtests",  ruleKey)

		rdb.Do("HSET", ruleKey, "serviceName", rule.ServiceName)
		rdb.Do("HSET", ruleKey, "name", rule.Name)
		rdb.Do("HSET", ruleKey, "enable", rule.Enable)
		rdb.Do("HSET", ruleKey, "desc", rule.Desc)
		rdb.Do("HSET", ruleKey, "host", rule.Host)
		rdb.Do("HSET", ruleKey, "priority", rule.Priority)
		rdb.Do("HSET", ruleKey, "strategy", rule.Strategy)
		rdb.Do("HSET", ruleKey, "list", rule.List)
		rdb.Do("HSET", ruleKey, "percent", rule.Percent)
		rdb.Do("HSET", ruleKey, "version", rule.Version)
		rdb.Do("HSET", ruleKey, "urlMatchKey", rule.UrlMatchKey)
	}

}
