package abtest

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/unnoo/abtest/redis"
	"math/rand"
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
	config *Config
	next   http.Handler
	logger *Logger
	redis  redis.Conn
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logger := NewLogger(config.LogLevel)
	logger.Info("create new plugin,", "name", name)

	configCopy := *config
	configCopy.RedisPassword = "******"
	logger.Debug(fmt.Sprintf("config info is %+v", configCopy))

	rand.Seed(time.Now().Unix())

	abtest := &Abtest{
		next:   next,
		config: config,
		logger: logger,
	}

	if config.Rules != nil && len(config.Rules) > 0 {
		sort.Sort(SortByPriority(abtest.config.Rules))
	}

	abtest.startLoadConfig()
	return abtest, nil
}

func (a *Abtest) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	a.logger.Debug(fmt.Sprintf("rules is %+v", a.config.Rules))

	if a.config.Rules != nil && len(a.config.Rules) > 0 {
		for _, rule := range a.config.Rules {
			if !rule.Enable {
				continue
			}
			if a.config.ServiceName != rule.ServiceName {
				continue
			}

			switch rule.Strategy {
			case StrategyPath:
				ok, err := a.matchByPath(rule, req)
				if err != nil || !ok {
					a.logger.Error("match path failed,", "error", err, "ok", ok)
					continue
				}
				target, err := a.getProxyTargetByRule(rule)
				if err != nil {
					a.logger.Error("match path failed,", "error", err)
					continue
				}

				a.logger.Info("match path success,", "target", target)
				a.reverseProxy(rw, req, target, rule)
				return
			case StrategyList:
				ok, err := a.matchByIdentify(rule, req)
				if err != nil || !ok {
					a.logger.Error("match user_id failed,", "error", err, "ok", ok)
					continue
				}
				target, err := a.getProxyTargetByRule(rule)
				if err != nil {
					a.logger.Error("match user_id failed,", "target", target, "error", err)
					continue
				}

				a.logger.Info("match user_id success,", "target", target)
				a.reverseProxy(rw, req, target, rule)
				return
			case StrategyVersion:
				ok, err := a.matchByVersion(rule, req)
				if err != nil || !ok {
					a.logger.Error("match version failed,", "error", err, "ok", ok)
					continue
				}
				target, err := a.getProxyTargetByRule(rule)
				if err != nil {
					a.logger.Error("match version failed,", "target", target, "error", err)
					continue
				}
				a.reverseProxy(rw, req, target, rule)
				return
			case StrategyPercent:
				ok, err := a.matchByPercent(rule, req)
				if err != nil || !ok {
					a.logger.Error("match percent failed,", "error", err, "ok", ok)
					continue
				}
				target, err := a.getProxyTargetByRule(rule)
				if err != nil {
					a.logger.Error("match percent failed,", "target", target, "error", err)
					continue
				}

				a.reverseProxy(rw, req, target, rule)
				return
			}
		}
	}

	// default
	a.logger.Info("rules is empty", "config", fmt.Sprintf("%+v", a.config))
	a.next.ServeHTTP(rw, req)
}

func (a *Abtest) startLoadConfig() {
	if !a.config.RedisEnable {
		return
	}
	a.redis = newRedis(a.config.RedisAddr, a.config.RedisPassword)

	go func() {
		a.logger.Info("load config ticker running...")
		timeTicker := time.NewTicker(time.Duration(a.config.RedisLoadInterval) * time.Second)

		// 用不了syscall.SIGTERM，就不处理退出事件了
		for {
			select {
			case <-timeTicker.C:
				a.logger.Debug("reload config")
				err := a.reloadConfig()
				if err != nil {
					a.logger.Error("load config failed,", "error", err)
				}
			}
		}
	}()
}

func (a *Abtest) reverseProxy(rw http.ResponseWriter, req *http.Request, target *url.URL, rule Rule) {
	a.logger.Debug("reverseProxy", "from", req.URL, "to", target)

	if a.config.RespCookieEnable {
		http.SetCookie(rw, &http.Cookie{
			Name:    a.config.RespCookieKey,
			Value:   rule.Env,
			Path:    "/",
			Domain:  a.parseHigherHost(req.Host), // 这里返回上一级的域名
			Expires: time.Now().Add(time.Duration(a.config.RespCookieExpire) * time.Second),
		})
	}

	// 替换req的host，否则会导致解析不正确
	req.Host = target.Host
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ServeHTTP(rw, req)
}

func (a *Abtest) getProxyTargetByRule(rule Rule) (*url.URL, error) {
	hosts := rule.Hosts
	if len(hosts) <= 0 {
		return nil, errors.New("rule hosts is empty")
	}
	i := 0
	count := len(hosts)
	if count > 1 {
		i = rand.Intn(count)
	}
	targetHost := hosts[i]
	target, err := url.ParseRequestURI(targetHost)
	if err != nil {
		return nil, err
	}
	return target, nil
}

func (a *Abtest) reloadConfig() error {
	ruleKeys, err := redis.Strings(a.redis.Do("LRANGE", a.config.RedisRulesKey, 0, a.config.RedisMaxRuleLen))
	if err != nil {
		return err
	}

	if len(ruleKeys) <= 0 {
		return errors.New("ruleKeys is empty")
	}

	rules := make([]Rule, 0, len(ruleKeys))

	for _, ruleKey := range ruleKeys {
		values, err := redis.Values(a.redis.Do("HGETALL", ruleKey))
		if err != nil {
			a.logger.Error("get rule failed,", "key", ruleKey, "error", err)
			continue
		}

		rule, err := parseRule(values)
		if err != nil {
			a.logger.Error("parse rule failed,", "error", err)
			continue
		}
		rules = append(rules, rule)
	}

	sort.Sort(SortByPriority(rules))
	a.config.Rules = rules

	return nil
}

func (a *Abtest) matchByIdentify(rule Rule, req *http.Request) (bool, error) {
	requestIdentify, err := a.getUserIdentifyByRequest(req)
	if err != nil {
		return false, nil
	}

	for _, userId := range rule.List {
		userIdentify, err := a.genUserIdentity(userId)
		if err != nil {
			a.logger.Error("genUserIdentity failed,", "error", err)
			continue
		}

		if userIdentify == requestIdentify {
			return true, nil
		}
	}

	return false, nil
}

func (a *Abtest) genUserIdentity(userId int64) (string, error) {
	key := fmt.Sprintf("%s_%d", a.config.UserIdentifyPrefix, userId)
	hash := md5.Sum([]byte(key))
	return strings.ToUpper(fmt.Sprintf("%x", hash))[0:16], nil
}

func (a *Abtest) getUserIdentifyByRequest(req *http.Request) (string, error) {
	token, err := a.getAccessToken(req)
	if err != nil {
		return "", err
	}
	if len(token) < 16 {
		return "", errors.New("invalid token")
	}

	return token[len(token)-16:], nil
}

func (a *Abtest) getAccessToken(req *http.Request) (string, error) {
	// 优先级 header -> cookie -> query
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
		return "", errors.New("accessToken is missing")
	}

	return token, nil
}

func (a *Abtest) matchByPath(rule Rule, req *http.Request) (bool, error) {
	if strings.Index(req.URL.String(), rule.Path) >= 0 {
		return true, nil
	}
	return false, nil
}

func (a *Abtest) matchByVersion(rule Rule, req *http.Request) (bool, error) {
	requestVersion := req.Header.Get(a.config.HeaderVersion)
	if a.compareVersion(requestVersion, rule.MinVersion) >= 0 && a.compareVersion(rule.MaxVersion, requestVersion) >= 0 {
		return true, nil
	}

	return false, nil
}

func (a *Abtest) compareVersion(version1, version2 string) int {
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

func (a *Abtest) matchByPercent(rule Rule, req *http.Request) (bool, error) {
	userId, err := a.accessTokenToNumber(req)
	if err != nil {
		a.logger.Error("accessTokenToNumber failed,", "error", err)
		return false, nil
	}

	if userId%100 <= rule.Percent {
		return true, nil
	}
	return false, nil
}

func (a *Abtest) accessTokenToNumber(req *http.Request) (int, error) {
	token, err := a.getAccessToken(req)
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

func (a *Abtest) parseHigherHost(host string) string {
	arr := strings.Split(host, ".")
	if len(arr) <= 2 {
		return host
	}
	return strings.Join(arr[1:], ".")
}
