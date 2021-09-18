package abtest

// Config the plugin configuration.
type Config struct {
	Rules    []rule `json:"rules"`
	Addr     string `json:"addr"`
	Password string `json:"password"`
}

type rule struct {
	Name     string      `json:"name"`
	Stratege string      `json:"stratege"`
	Host     string      `json:"host"`
	Priority int         `json:"priority"`
	Enable   bool        `json:"enable"`
	Details  interface{} `json:"details"`
}

type percentStratege int

type versionStratege struct {
	MinVersion string `json:"min_version"`
	MaxVersion string `json:"max_version"`
}

type cookieStratege struct {
	CookieName string `json:"cookie_name"`
	List       string `json:"list"`
}

type authorizationStratege struct {
	List string `json:"list"`
}
