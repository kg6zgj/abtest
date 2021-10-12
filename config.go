package abtest

import (
	"errors"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"strconv"
	"strings"
)

type Config struct {
	ServiceName   string `json:"serviceName"`   // 当前middle生效的ServiceName
	RedisAddr     string `json:"redisAddr"`     // redis地址
	RedisPassword string `json:"redisPassword"` // redis密码
	RedisEnable   bool   `json:"redisEnable"`   // 是否开启redis
	Rules         []Rule `json:"rules"`         // 灰度规则

	RespCookieEnable   bool   `json:"respCookieEnable"`   // 成功代理后是否设置cookie
	RespCookieKey      string `json:"respCookieKey"`      // 成功代理后设置cookie的key
	RespCookieExpire   int    `json:"respCookieExpire"`   // 成功代理后cookie过期时间
	UserIdentifyPrefix string `json:"userIdentifyPrefix"` // 用户身份匹配前缀
	HeaderAccessToken  string `json:"headerAccessToken"`  // 请求头里的AccessToken
	QueryAccessToken   string `json:"queryAccessToken"`   // 请求url的AccessToken
	CookieAccessToken  string `json:"cookieAccessToken"`  // cookie里的AccessToken
	HeaderVersion      string `json:"headerVersion"`      // 请求头里的Version
	RedisRulesKey      string `json:"redisRulesKey"`      // redis rule key
	RedisMaxRuleLen    int    `json:"redisMaxRuleLen"`    // redis max rule len
	RedisLoadInterval  int64  `json:"redisLoadInterval"`  // redis load interval
}

const (
	StrategyVersion = "version"
	StrategyList    = "list"
	StrategyPercent = "percent"
	StrategyUrl     = "match_url"
)

const (
	KeyServiceName = "serviceName"
	KeyName        = "name"
	KeyEnable      = "enabled"
	KeyDesc        = "desc"
	KeyHosts       = "hosts"
	KeyPriority    = "priority"
	KeyStrategy    = "stratege"
	KeyList        = "list"
	KeyPercent     = "percent"
	KeyVersion     = "version"
	KeyUrlMatchKey = "match_url"
)

// Rule 存在redis中的灰度规则
type Rule struct {
	ServiceName string   `json:"serviceName"` // 这个规则对应的serviceName, 必须要指定
	Env         string   `json:"env"`         // alpha ｜ beta
	Name        string   `json:"name"`        // 规则名字
	Enable      bool     `json:"enable"`      // 是否开启
	Desc        string   `json:"desc"`        // 规则描述。输出到日志中，建议简短描述。
	Hosts       []string `json:"hosts"`       // 转发的目标URL，多个目标以逗号分隔。如："http://1/,http://2/"。
	Priority    int      `json:"priority"`    // 优先级
	Strategy    string   `json:"Strategy"`    // 策略。有效值："list" - 只转发指定user_id的请求，"percent" - 按用户的百分比转发，"version" - 只转发指定范围版本的请求。
	List        []int64  `json:"list"`        // （可选，仅当strategy为"list"时有效）需要转发请求的用户ID。多个ID以逗号分隔。如："1,5,9"。
	Percent     int      `json:"percent"`     // （可选，仅当strategy为"percent"时有效）百分比。比如："10"。
	MinVersion  string   `json:"minVersion"`  // （可选，仅当strategy为"version"时有效）最小版本。比如："1.8.3",
	MaxVersion  string   `json:"maxVersion"`  // （可选，仅当strategy为"version"时有效）最大版本。比如："1.8.3"
	UrlMatchKey string   `json:"urlMatchKey"` // （可选，仅当strategy为"match_url"时有效) ab_test
}

// ParseRule 解析Redis读到的rule规则
// format ["serviceName", "foo", "enable", 1]
func ParseRule(values []interface{}) (Rule, error) {
	if len(values)%2 != 0 {
		return Rule{}, errors.New("expects even number of values result")
	}

	r := Rule{}

	for i := 0; i < len(values); i += 2 {
		key, okKey := values[i].([]byte)
		if !okKey {
			return r, fmt.Errorf("expects type for String, got type %T", values[i])
		}
		value := values[i+1]

		switch string(key) {
		case KeyServiceName:
			serviceName, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			r.ServiceName = serviceName
		case KeyName:
			name, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			r.Name = name
		case KeyEnable:
			enable, err := redis.Bool(value, nil)
			if err != nil {
				return r, err
			}
			r.Enable = enable
		case KeyDesc:
			desc, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			r.Desc = desc
		case KeyHosts:
			hostsStr, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			hostArr := strings.Split(hostsStr, ",")
			for index, host := range hostArr {
				hostArr[index] = strings.TrimSpace(host)
			}
			r.Hosts = hostArr

		case KeyPriority:
			priority, err := redis.Int(value, nil)
			if err != nil {
				return r, err
			}
			r.Priority = priority
		case KeyStrategy:
			Strategy, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			r.Strategy = Strategy
		case KeyList:
			list, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			listArr := strings.Split(list, ",")
			intList := make([]int64, len(listArr))
			for index, userId := range listArr {
				if uid, err := strconv.Atoi(userId); err == nil {
					intList[index] = int64(uid)
				}
			}
			r.List = intList
		case KeyPercent:
			percent, err := redis.Int(value, nil)
			if err != nil {
				return r, err
			}
			r.Percent = percent
		case KeyVersion:
			version, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			versionArr := strings.Split(version, "-")
			if len(versionArr) != 2 {
				return r, errors.New(fmt.Sprintf("new roule error, version [%s] invalid", KeyVersion))
			}

			r.MinVersion = versionArr[0]
			r.MaxVersion = versionArr[1]
		case KeyUrlMatchKey:
			matchKey, err := redis.String(value, nil)
			if err != nil {
				return r, err
			}
			r.UrlMatchKey = matchKey
		}

	}
	return r, nil
}

type SortByPriority []Rule

func (a SortByPriority) Len() int           { return len(a) }
func (a SortByPriority) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortByPriority) Less(i, j int) bool { return a[i].Priority > a[j].Priority }
