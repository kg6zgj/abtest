package abtest

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Example a plugin.
type Abtest struct {
	next http.Handler
	// ...
	rules []rule
}

type SortByPiority []rule

func (a SortByPiority) Len() int           { return len(a) }
func (a SortByPiority) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SortByPiority) Less(i, j int) bool { return a[i].Priority < a[j].Priority }

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// ...
	log.Printf("%+v", config)
	initRedis(config.Addr, config.Password)
	return &Abtest{
		next:  next,
		rules: config.Rules,
	}, nil
}

func (a *Abtest) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ...
	log.Printf("%+v", req.URL.String())
	log.Printf("%+v", req.Host)
	log.Printf("%+v", req.URL.Path)
	log.Printf("%+v", req.URL.RawQuery)
	log.Printf("%+v", req.URL.Scheme)
	if len(a.rules) == 0 {
		a.next.ServeHTTP(rw, req)
		return
	}

	destination := getProxyURL(req.URL, a.rules)
	log.Printf("dest: %v", destination)
	// req.URL.Host = newHost
	// req.RequestURI = req.URL.RequestURI()

	log.Printf("%+v", req.URL)
	proxyHTTPRequest(rw, req, destination)
}

func getProxyURL(u *url.URL, rules []rule) (destination string) {
	sort.Sort(SortByPiority(rules))
	log.Printf("%+v", rules)
	host := u.Host
	for _, rule := range rules {
		if rule.Enable {
			host = rule.Host
			break
		}
	}
	return fmt.Sprintf("https://%s%s", host, u.String())
}

func proxyHTTPRequest(rw http.ResponseWriter, req *http.Request, destination string) {
	parsedURL, err := url.Parse(destination)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	reqClone := req.Clone(context.TODO())
	reqClone.URL = parsedURL
	reqClone.Host = parsedURL.Host
	reqClone.RequestURI = ""
	httpClient := http.Client{}
	resp, err := httpClient.Do(reqClone)
	log.Printf("%+v", reqClone.URL)

	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		return
	}
	for key := range resp.Header {
		value := resp.Header.Get(key)
		rw.Header().Add(key, value)
	}
	rw.WriteHeader(resp.StatusCode)
	_, err = io.Copy(rw, resp.Body)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		resp.Body.Close()
		return
	}
	resp.Body.Close()
}
