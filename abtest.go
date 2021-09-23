package abtest

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func CreateConfig() *Config {
	return &Config{}
}

type Abtest struct {
	next         http.Handler // next
	logger       *Logger      // logger
	loadInterval int64        // 加载时间间隔
	config       *Config      // 配置
	rules        []Rule       // 灰度规则
}

func LoadConfig(abtest *Abtest) {
	if !abtest.config.RedisEnable {
		return
	}

	go func() {
		abtest.logger.Debug("load config run")
		timeTicker := time.NewTicker(time.Duration(abtest.config.RedisLoadInterval) * time.Second)

		for {
			select {
			case <-timeTicker.C:
				abtest.logger.Debug("reload config")
				err := abtest.ReloadConfig()
				if err != nil {
					abtest.logger.Error("load config error", err)
				}
			}
		}
	}()
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	initLogger()

	if config.RedisEnable {
		initRedis(config.RedisAddr, config.RedisPassword)
	}

	// sort rules
	sort.Sort(SortByPriority(config.Rules))

	abtest := &Abtest{
		next:         next,
		config:       config,
		logger:       logger,
		loadInterval: config.RedisLoadInterval,
		rules:        config.Rules,
	}

	LoadConfig(abtest)
	return abtest, nil
}

func (a *Abtest) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if a.rules != nil && len(a.rules) > 0 {
		matchIndex, err := a.MatchByUrlRule(req)
		if err == nil {
			target, err := a.GetProxyTargetByRule(matchIndex)
			if err != nil {
				a.logger.Error("match url rule error ", "target", target, "err", err)
				a.next.ServeHTTP(rw, req)
				return
			}
			a.logger.Debug("match url rule", "target", target)
			a.ReverseProxy(rw, req, target)
			return
		}

		// match by user
		matchIndex, err = a.MatchByUserRule(req)
		if err == nil {
			target, err := a.GetProxyTargetByRule(matchIndex)
			if err != nil {
				a.logger.Error("match user rule error ", "target", target, "err", err)
				a.next.ServeHTTP(rw, req)
				return
			}

			a.logger.Debug("match user rule", "target", target)
			a.ReverseProxy(rw, req, target)
			return
		}

		// match by version
		matchIndex, err = a.MatchByVersionRule(req)
		if err == nil {
			target, err := a.GetProxyTargetByRule(matchIndex)
			if err != nil {
				a.logger.Error("match version rule error", "target", target, "err", err)
				a.next.ServeHTTP(rw, req)
				return
			}

			a.logger.Debug("match version rule", "target", target)
			a.ReverseProxy(rw, req, target)
			return
		}

		// match by percent
		matchIndex, err = a.MatchByPercentRule(req)
		if err == nil {
			target, err := a.GetProxyTargetByRule(matchIndex)
			if err != nil {
				a.logger.Error("match percent rule error", "target", target, "err", err)
				a.next.ServeHTTP(rw, req)
				return
			}

			a.logger.Debug("match percent rule", "target", target)
			a.ReverseProxy(rw, req, target)
			return
		}
	}

	a.logger.Info("not match target")
	a.next.ServeHTTP(rw, req)
	return
}

// ReverseProxy 反向代理请求！
func (a *Abtest) ReverseProxy(rw http.ResponseWriter, req *http.Request, target *url.URL) {
	a.logger.Info("ReverseProxy", "from", req.URL, "to host", target)

	// 替换req的host，否则会导致解析不正确
	req.Host = target.Host
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ServeHTTP(rw, req)
}

// GetProxyTargetByRule 通过规则获取代理目标url
func (a *Abtest) GetProxyTargetByRule(ruleIndex int) (*url.URL, error) {
	if ruleIndex >= len(a.rules) {
		return nil, errors.New("index out of rules")
	}

	rule := a.rules[ruleIndex]
	hosts := rule.Hosts
	i := 0
	count := len(hosts)
	if count > 1 {
		i = int(math.Floor(float64(time.Now().Unix() % int64(count))))
	}
	targetHost := hosts[i]
	target, err := url.ParseRequestURI(targetHost)
	if err != nil {
		return nil, err
	}
	return target, nil
}

// ReloadConfig 重新加载配置
func (a *Abtest) ReloadConfig() error {
	// 加载配置
	rdb := GetRedisInst()

	ruleKeys, err := redis.Strings(rdb.Do("LRANGE", a.config.RedisRulesKey, 0, a.config.RedisMaxRuleLen))
	if err != nil {
		return err
	}
	if len(ruleKeys) <= 0 {
		return errors.New("ruleKeys is empty")
	}

	rules := make([]Rule, 0, len(ruleKeys))

	for _, ruleKey := range ruleKeys {
		values, err := redis.Values(rdb.Do("HGETALL", ruleKey))
		if err != nil {
			a.logger.Error("get rule by ruleKey error", "key", ruleKey, "err", err)
			continue
		}

		rule, err := NewRule(values)
		if err != nil {
			a.logger.Error("parse rule err ", err)
			continue
		}

		rules = append(rules, rule)
	}

	sort.Sort(SortByPriority(rules))

	a.rules = rules
	a.config.Rules = rules
	return nil
}

// MatchByUserRule 匹配用户
func (a *Abtest) MatchByUserRule(req *http.Request) (int, error) {
	requestIdentify, err := a.GetUserIdentifyByRequest(req)
	if err != nil {
		return 0, err
	}

	for index, rule := range a.rules {
		if !rule.Enable || rule.Stratege != StrategeList || rule.ServiceName != a.config.ServiceName {
			continue
		}

		for _, userId := range rule.List {
			userIdentify, err := a.GenUserIdentity(userId)
			if err != nil {
				a.logger.Error("get user identity is error", err)
				continue
			}

			if userIdentify == requestIdentify {
				return index, nil
			}
		}
	}

	return 0, errors.New("not match")
}

// GenUserIdentity 通过UserId生成身份认证
func (a *Abtest) GenUserIdentity(userId int64) (string, error) {
	key := fmt.Sprintf("%s_%d", a.config.UserIdentifyPrefix, userId)
	hash := md5.Sum([]byte(key))
	return strings.ToUpper(fmt.Sprintf("%x", hash))[0:16], nil
}

// GetUserIdentifyByRequest 获取请求头里的身份认证
func (a *Abtest) GetUserIdentifyByRequest(req *http.Request) (string, error) {
	token, err := a.GetAccessToken(req)
	if err != nil {
		return "", err
	}
	if len(token) < 16 {
		return "", errors.New("invalid token")
	}

	return token[0:16], nil
}

// GetAccessToken 获取access_token
func (a *Abtest) GetAccessToken(req *http.Request) (string, error) {
	// header -> cookie -> query
	token := req.Header.Get(a.config.HeaderAccessToken)
	if token == "" {
		cookie, err := req.Cookie(a.config.CookieAccessToken)
		if err == nil && cookie.Value != "" {
			token = cookie.Value
		}
	}
	if token == "" {
		token = req.URL.Query().Get(a.config.QueryAccessToken)
	}

	if token == "" {
		return "", errors.New("access_token is missing")
	}

	return token, nil
}

// GetRequestHeader 获取请求头。多个只返回一个
func (a *Abtest) GetRequestHeader(req *http.Request, key string) string {
	return req.Header.Get(key)
}

func (a *Abtest) MatchByUrlRule(req *http.Request) (int, error) {
	if strings.Index(req.URL.String(), "abtest_env") < 0 {
		return 0, errors.New("not match")
	}
	for index, rule := range a.rules {
		if !rule.Enable || rule.Stratege != StrategeUrl || rule.ServiceName != a.config.ServiceName {
			continue
		}
		// return first match
		return index, nil
	}
	return 0, errors.New("not match")
}

// MatchByVersionRule 匹配版本规则
func (a *Abtest) MatchByVersionRule(req *http.Request) (int, error) {
	for index, rule := range a.rules {
		if !rule.Enable || rule.Stratege != StrategeVersion || rule.ServiceName != a.config.ServiceName {
			continue
		}

		requestVersion := a.GetRequestHeader(req, a.config.HeaderVersion)

		if a.CompareVersion(requestVersion, rule.MinVersion) >= 0 && a.CompareVersion(rule.MaxVersion, requestVersion) >= 0 {
			return index, nil
		}
	}
	return 0, errors.New("not match")
}

// CompareVersion 比较版本
func (a *Abtest) CompareVersion(version1, version2 string) int {
	v1 := strings.Split(version1, ".")
	v2 := strings.Split(version2, ".")
	for i := 0; i < len(v1) || i < len(v2); i++ {
		x, y := 0, 0
		if i < len(v1) {
			x, _ = strconv.Atoi(v1[i])
		}
		if i < len(v2) {
			y, _ = strconv.Atoi(v2[i])
		}
		if x > y {
			return 1
		}
		if x < y {
			return -1
		}
	}
	return 0
}

// MatchByPercentRule 匹配灰度规则
func (a *Abtest) MatchByPercentRule(req *http.Request) (int, error) {
	for index, rule := range a.rules {
		if !rule.Enable || rule.Stratege != StrategePercent || rule.ServiceName != a.config.ServiceName {
			continue
		}

		userId, err := a.AccessTokenToNumber(req)
		if err != nil {
			a.logger.Error("AccessTokenToNumber error", err)
			continue
		}

		if userId%100 <= rule.Percent {
			return index, nil
		}
	}

	return 0, errors.New("not match")
}

// AccessTokenToNumber 解析token到Number
func (a *Abtest) AccessTokenToNumber(req *http.Request) (int, error) {
	token, err := a.GetAccessToken(req)
	if err != nil {
		return 0, err
	}

	tokenArr := []byte(token[1:16])
	result := 0
	for _, value := range tokenArr {
		result += int(value)
	}

	return result, nil
}
