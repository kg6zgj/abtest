package abtest

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"sort"
	"strings"
	"testing"
)

var (
	HeaderAccessToken = "Authorization"
	QueryAccessToken  = "access_token"
	CookieAccessToken = "zsxq_access_token"
	HeaderVersion     = "X-Version"
	RedisRulesKey     = "abtests"
	RedisMaxRules     = 256
)
var (
	host         = "test.api.cn"
	alphaService = "https://alpha.api.cn"
	betaService  = "https://beta.api.cn"
	testService  = "https://test.api.cn"
)

func newConfig() *Config {
	return &Config{
		ServiceName:        "api",
		RedisAddr:          "127.0.0.1:6379",
		RedisPassword:      "",
		RedisEnable:        false,
		UserIdentifyPrefix: "zsxq",
		HeaderAccessToken:  HeaderAccessToken,
		QueryAccessToken:   QueryAccessToken,
		CookieAccessToken:  CookieAccessToken,
		HeaderVersion:      HeaderVersion,
		RedisRulesKey:      RedisRulesKey,
		RedisMaxRuleLen:    RedisMaxRules,
		Rules: []Rule{
			{
				ServiceName: "api",
				Name:        "api",
				Enable:      true,
				Desc:        "api1",
				Hosts:       []string{alphaService, betaService, testService},
				Priority:    0,
				Stratege:    StrategeList,
				Percent:     0,
				MinVersion:  "3.3.3",
				MaxVersion:  "4.4.4",
			},
			{
				ServiceName: "api",
				Name:        "api1",
				Enable:      true,
				Desc:        "api1",
				Hosts:       []string{alphaService, betaService, testService},
				Priority:    1,
				Stratege:    StrategeList,
				Percent:     0,
				MinVersion:  "1.1.1",
				MaxVersion:  "2.2.2",
			},
		},
	}
}

//func TestGetProxyTargetByRule(t *testing.T) {
//
//}
//
//func TestMatchByUserRule(t *testing.T) {
//
//}
//
func TestGenUserIdentity(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, "ab_test")
	assert.Equal(t, err, nil)
	var obj interface{} = handler
	ab := obj.(*Abtest)

	identify, err := ab.GenUserIdentity(64)
	assert.Equal(t, err, nil)
	assert.Equal(t, identify, strings.ToUpper("02872858c09444e8527c084a401662ba")[0:16])
	identify, err = ab.GenUserIdentity(1000)
	assert.Equal(t, err, nil)
	assert.Equal(t, identify, strings.ToUpper("238ee05097754cc028e8535fcc0efd56")[0:16])
}

func TestGetUserIdentifyByRequest(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, "ab_test")
	assert.Equal(t, err, nil)

	var obj interface{} = handler
	ab := obj.(*Abtest)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://test.api.cn", nil)
	assert.Equal(t, err, nil)

	// GenUserIdentity
	token := "6d0b865b7d33c81b43fabaf044a35f76"
	req := request.Clone(ctx)
	req.Header.Set(HeaderAccessToken, token)
	userIdentify, err := ab.GetUserIdentifyByRequest(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, userIdentify, token[0:16])

	req = request.Clone(ctx)
	userIdentify, err = ab.GetUserIdentifyByRequest(req)
	assert.NotEqual(t, err, nil)
	assert.Equal(t, userIdentify, "")

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://test.api.cn?%s=%s", QueryAccessToken, token), nil)
	userIdentify, err = ab.GetUserIdentifyByRequest(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, userIdentify, token[0:16])

	req = req.Clone(ctx)
	req.AddCookie(&http.Cookie{Name: CookieAccessToken, Value: token})
	req.Header.Add(CookieAccessToken, token)
	userIdentify, err = ab.GetUserIdentifyByRequest(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, userIdentify, token[0:16])
}

func TestGetAccessToken(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, "ab_test")
	assert.Equal(t, err, nil)
	var obj interface{} = handler
	ab := obj.(*Abtest)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://test.api.cn", nil)
	assert.Equal(t, err, nil)

	// GenUserIdentity
	token := "6d0b865b7d33c81b43fabaf044a35f76"
	req := request.Clone(ctx)
	req.Header.Set(HeaderAccessToken, token)
	getToken, err := ab.GetAccessToken(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, getToken, token)

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://test.api.cn?%s=%s", QueryAccessToken, token), nil)
	getToken, err = ab.GetAccessToken(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, getToken, token)
}

//
//func TestIsContainTargetUser(t *testing.T) {
//
//}
//
//func TestGetRequestHeader(t *testing.T) {
//
//}
//
//func TestMatchByVersionRule(t *testing.T) {
//
//}

func TestCompareVersion(t *testing.T) {
	config := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, "ab_test")
	assert.Equal(t, err, nil)
	var obj interface{} = handler
	ab := obj.(*Abtest)

	// CompareVersion
	assert.Equal(t, ab.CompareVersion("1.1.1", "1.1.2"), -1)
	assert.Equal(t, ab.CompareVersion("1.1.1", "1.1.1.0"), 0)
	assert.Equal(t, ab.CompareVersion("1.1.2", "1.1.1"), 1)
	assert.Equal(t, ab.CompareVersion("1.1.1", "1.1.1"), 0)
}

//func TestMatchByPercentRule(t *testing.T) {
//
//}
//
//func TestAccessTokenToNumber(t *testing.T) {
//
//}

func TestLoadConfig(t *testing.T) {
	config := newConfig()
	config.RedisEnable = true
	config.RedisLoadInterval = 3
	config.Rules = nil
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, "ab_test")
	assert.Equal(t, err, nil)

	var obj interface{} = handler
	ab := obj.(*Abtest)

	err = ab.ReloadConfig()
	t.Log("load config result ", err)
	v, _ := json.Marshal(ab.config.Rules)
	t.Log("load config: config is ", string(v))
	assert.Equal(t, err, nil)
}

func TestSortByPriority(t *testing.T) {
	rules := []Rule{
		{Priority: 10},
		{Priority: 111},
		{Priority: 3},
	}
	sort.Sort(SortByPriority(rules))
	for index, rule := range rules {
		t.Log("index", index, "rule.Priority", rule.Priority)
	}
}
