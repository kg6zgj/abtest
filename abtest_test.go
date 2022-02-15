package abtest

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"sort"
	"testing"
)

var (
	name              = "abtest"
	HeaderAccessToken = "token"
	QueryAccessToken  = "token"
	CookieAccessToken = "token"
	HeaderVersion     = "version"
	alphaService      = "https://alpha.api.cn"
	betaService       = "https://beta.api.cn"
	testService       = "https://test.api.cn"
)

func newConfig() *Config {
	return &Config{
		ServiceName:        "api",
		RedisAddr:          "",
		RedisPassword:      "",
		RedisEnable:        false,
		RedisRulesKey:      "",
		RedisMaxRuleLen:    0,
		UserIdentifyPrefix: "",
		HeaderAccessToken:  HeaderAccessToken,
		QueryAccessToken:   QueryAccessToken,
		CookieAccessToken:  CookieAccessToken,
		HeaderVersion:      HeaderVersion,
		Rules: []Rule{
			{
				ServiceName: "api",
				Name:        "alpha",
				Enable:      true,
				Desc:        "alpha",
				Hosts:       []string{alphaService, betaService, testService},
				Priority:    0,
				Strategy:    StrategyList,
				Percent:     0,
				List:        []int64{1, 2, 3},
				MinVersion:  "3.3.3",
				MaxVersion:  "4.4.4",
				Path:        "alpha",
			},
			{
				ServiceName: "api",
				Name:        "api-1",
				Enable:      true,
				Desc:        "api1",
				Hosts:       []string{alphaService, betaService, testService},
				Priority:    1,
				Strategy:    StrategyList,
				Percent:     0,
				List:        []int64{1, 2, 3},
				MinVersion:  "1.1.1",
				MaxVersion:  "2.2.2",
			},
		},
	}
}

func TestMatchByVersion(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)
	rule := Rule{
		ServiceName: "api",
		Name:        "alpha",
		Enable:      true,
		Hosts:       []string{alphaService},
		Strategy:    StrategyVersion,
		MinVersion:  "1.1.1",
		MaxVersion:  "2.2.2",
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, testService, nil)
	request.Header.Add(HeaderVersion, "1.1.1")
	assert.Equal(t, err, nil)
	ok, err := ab.matchByVersion(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, testService, nil)
	request.Header.Add(HeaderVersion, "1.1.2")
	assert.Equal(t, err, nil)
	ok, err = ab.matchByVersion(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, testService, nil)
	request.Header.Add(HeaderVersion, "3.3.3")
	assert.Equal(t, err, nil)
	ok, err = ab.matchByVersion(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, false)
}

func TestMatchByList(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)
	rule := Rule{
		ServiceName: "api",
		Name:        "alpha",
		Enable:      true,
		Hosts:       []string{alphaService},
		Strategy:    StrategyList,
		List:        []int64{1, 2},
	}
	tokens := []string{"5D98EC0427152056", "26E3D8BAC39F9313", "26E3D8BAC39F9313_xx"}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, tokens[0]), nil)
	assert.Equal(t, err, nil)
	ok, err := ab.matchByIdentify(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, tokens[1]), nil)
	assert.Equal(t, err, nil)
	ok, err = ab.matchByIdentify(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, tokens[2]), nil)
	assert.Equal(t, err, nil)
	ok, err = ab.matchByIdentify(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, false)
}

func TestMatchByPercent(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)
	rules := []Rule{
		{
			ServiceName: "api",
			Name:        "alpha",
			Enable:      true,
			Hosts:       []string{alphaService},
			Strategy:    StrategyPercent,
			Percent:     0,
		},
		{
			ServiceName: "api",
			Name:        "alpha",
			Enable:      true,
			Hosts:       []string{alphaService},
			Strategy:    StrategyPercent,
			Percent:     50,
		},
		{
			ServiceName: "api",
			Name:        "alpha",
			Enable:      true,
			Hosts:       []string{alphaService},
			Strategy:    StrategyPercent,
			Percent:     100,
		},
	}
	token := "6d0b865b7d33c81b43fabaf044a35f711"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, token), nil)
	assert.Equal(t, err, nil)
	ok, err := ab.matchByPercent(rules[0], request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, false)

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, token), nil)
	assert.Equal(t, err, nil)
	ok, err = ab.matchByPercent(rules[1], request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, token), nil)
	assert.Equal(t, err, nil)
	ok, err = ab.matchByPercent(rules[2], request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)
}

func TestMatchPath(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)
	rule := Rule{
		ServiceName: "api",
		Name:        "alpha",
		Enable:      true,
		Hosts:       []string{alphaService},
		Strategy:    StrategyPath,
		Path:        "alpha",
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, testService, nil)
	ok, err := ab.matchByPath(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, false)

	request, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/alpha", testService), nil)
	ok, err = ab.matchByPath(rule, request)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)
}

func TestGetProxyTargetByRule(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)

	testDataList := []struct {
		Rule        Rule
		ExpectHosts []string
	}{
		{
			Rule{Hosts: []string{testService, alphaService}},
			[]string{testService, alphaService},
		},
	}

	for _, data := range testDataList {
		target, err := ab.getProxyTargetByRule(data.Rule)
		assert.Equal(t, err, nil)
		actual := false

		for _, host := range data.ExpectHosts {
			if host == target.String() {
				actual = true
			}
		}

		assert.Equal(t, actual, true)
	}
}

func TestGenUserIdentity(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)

	testDataList := []struct {
		userId         int64
		ExpectIdentify string
	}{
		{
			1,
			"5D98EC0427152056",
		},
		{
			2,
			"26E3D8BAC39F9313",
		},
	}

	for _, data := range testDataList {
		identify, err := ab.genUserIdentity(data.userId)
		assert.Equal(t, err, nil)
		assert.Equal(t, data.ExpectIdentify, identify)
	}
}

func TestGetUserIdentifyByRequest(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, testService, nil)
	assert.Equal(t, err, nil)

	// header
	token := "6d0b865b7d33c81b43fabaf044a35f76"

	req := request.Clone(ctx)
	req.Header.Set(HeaderAccessToken, token)
	userIdentify, err := ab.getUserIdentifyByRequest(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, userIdentify, token[len(token)-16:])

	// query
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, token), nil)
	userIdentify, err = ab.getUserIdentifyByRequest(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, userIdentify, token[len(token)-16:])

	// cookie
	req = req.Clone(ctx)
	req.AddCookie(&http.Cookie{Name: CookieAccessToken, Value: token})
	req.Header.Add(CookieAccessToken, token)
	userIdentify, err = ab.getUserIdentifyByRequest(req)
	assert.Equal(t, err, nil)
	assert.Equal(t, userIdentify, token[len(token)-16:])

	// miss token
	req = request.Clone(ctx)
	userIdentify, err = ab.getUserIdentifyByRequest(req)
	assert.NotEqual(t, err, nil)
	assert.Equal(t, userIdentify, "")
}

func TestCompareVersion(t *testing.T) {
	config := CreateConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, "ab_test")
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)

	assert.Equal(t, ab.compareVersion("1.1.1", "1.1.2"), -1)
	assert.Equal(t, ab.compareVersion("1.1.1", "1.1.1.0"), 0)
	assert.Equal(t, ab.compareVersion("1.1.2", "1.1.1"), 1)
	assert.Equal(t, ab.compareVersion("1.1.1", "1.1.1"), 0)
}

func TestAccessTokenToNumber(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)

	testDataList := []struct {
		Token        string
		ExpectNumber int
	}{
		{
			"0000000000000000",
			768,
		},
		{
			"0000000000000001",
			769,
		},
		{
			"7316EB0C-BB00-9E38-9EE9-032BBBDF68CA_155D960446719750",
			903,
		},
	}

	for _, data := range testDataList {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, testService, nil)
		assert.Equal(t, err, nil)
		req.Header.Add(HeaderAccessToken, data.Token)
		number, err := ab.accessTokenToNumber(req)
		assert.Equal(t, err, nil)
		assert.Equal(t, data.ExpectNumber, number)
	}
}

func TestGetAccessToken(t *testing.T) {
	config := newConfig()
	ctx := context.Background()
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {})
	handler, err := New(ctx, next, config, name)
	assert.Equal(t, err, nil)
	ab := handler.(*Abtest)

	token := "7316EB0C-BB00-9E38-9EE9-032BBBDF68CA_155D960446719750"

	// get by cookie
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, testService, nil)
	assert.Equal(t, err, nil)
	request.AddCookie(&http.Cookie{Name: CookieAccessToken, Value: token})
	reqToken, err := ab.getAccessToken(request)
	assert.Equal(t, err, nil)
	assert.Equal(t, reqToken, token)

	// get by query
	request, err = http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("%s?%s=%s", testService, QueryAccessToken, token), nil)
	assert.Equal(t, err, nil)
	reqToken, err = ab.getAccessToken(request)
	assert.Equal(t, err, nil)
	assert.Equal(t, reqToken, token)

	// get by request healer
	request, err = http.NewRequestWithContext(context.Background(), http.MethodGet, testService, nil)
	assert.Equal(t, err, nil)
	request.Header.Add(HeaderAccessToken, token)
	reqToken, err = ab.getAccessToken(request)
	assert.Equal(t, err, nil)
	assert.Equal(t, reqToken, token)

	// miss token
	request, err = http.NewRequestWithContext(context.Background(), http.MethodGet, testService, nil)
	assert.Equal(t, err, nil)
	reqToken, err = ab.getAccessToken(request)
	assert.NotEqual(t, err, nil)
	assert.Equal(t, reqToken, "")
}

func TestParseHigherHost(t *testing.T) {
	a := Abtest{}
	testDataList := []struct {
		Host   string
		Expect string
	}{
		{
			"wx.api.com",
			"api.com",
		},
		{
			"wx.dev.api.com",
			"dev.api.com",
		},
		{
			"api.com",
			"api.com",
		},
		{
			"",
			"",
		},
	}

	for _, data := range testDataList {
		assert.Equal(t, a.parseHigherHost(data.Host), data.Expect)
	}
}

func TestSortByPriority(t *testing.T) {
	rules := []Rule{
		{Priority: 10},
		{Priority: 111},
		{Priority: 3},
	}
	sort.Sort(SortByPriority(rules))
	expectRules := []Rule{
		{Priority: 111},
		{Priority: 10},
		{Priority: 3},
	}
	for index, rule := range rules {
		assert.Equal(t, rule.Priority, expectRules[index].Priority)
	}
}
