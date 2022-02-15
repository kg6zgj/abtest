package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/unnoo/abtest/redis"
	"gopkg.in/yaml.v3"
	"log"
	"os"
)

var configFile = flag.String("c", "", "config file")

type Rule struct {
	ServiceName string `yaml:"service_name"`
	Name        string `yaml:"name"`
	Enabled     bool   `yaml:"enabled"`
	Desc        string `yaml:"desc"`
	Hosts       string `yaml:"hosts"`
	Priority    int    `yaml:"priority"`
	Strategy    string `yaml:"strategy"`
	List        string `yaml:"list"`
	Percent     int    `yaml:"percent"`
	Version     string `yaml:"version"`
	Path        string `yaml:"match_url"`
}

type Config struct {
	RedisAddr     string `yaml:"redisAddr"`
	RedisPassword string `yaml:"redisPassword"`
	RuleListKey   string `yaml:"ruleListKey"`
	Rules         []Rule `yaml:"rules"`
}

func main() {
	flag.Parse()
	log.Println("config file ", *configFile)
	data, err := os.ReadFile(*configFile)
	if err != nil {
		log.Println("read config failed, error", err)
		return
	}
	cfg := Config{}
	//log.Println("config data is ", string(data))
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		log.Println("unmarshal config failed, error", err)
		return
	}

	v, err := json.Marshal(cfg)
	log.Println(string(v), err)

	rdb, err := redis.Dial("tcp", cfg.RedisAddr, redis.DialPassword(cfg.RedisPassword))
	if err != nil {
		log.Println("init redis failed, error", err)
		return
	}

	for _, rule := range cfg.Rules {
		log.Println("insert rule ", rule.Name)
		ruleKey := fmt.Sprintf("abtest:%s", rule.Name)
		_, _ = rdb.Do("LPUSH", cfg.RuleListKey, ruleKey)

		_, _ = rdb.Do("HSET", ruleKey, "service_name", rule.ServiceName)
		_, _ = rdb.Do("HSET", ruleKey, "name", rule.Name)
		_, _ = rdb.Do("HSET", ruleKey, "enabled", rule.Enabled)
		_, _ = rdb.Do("HSET", ruleKey, "desc", rule.Desc)
		_, _ = rdb.Do("HSET", ruleKey, "hosts", rule.Hosts)
		_, _ = rdb.Do("HSET", ruleKey, "priority", rule.Priority)
		_, _ = rdb.Do("HSET", ruleKey, "strategy", rule.Strategy)
		_, _ = rdb.Do("HSET", ruleKey, "list", rule.List)
		_, _ = rdb.Do("HSET", ruleKey, "percent", rule.Percent)
		_, _ = rdb.Do("HSET", ruleKey, "version", rule.Version)
		_, _ = rdb.Do("HSET", ruleKey, "match_url", rule.Path)
	}
}
