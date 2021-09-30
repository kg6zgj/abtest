abtest
---------------------------
A traefik Plugin store abtest rules in Redis

### Static Configuration

```yaml
experimental:
  plugins:
    abtest:
      moduleName: github.com/unnoo/abtest

pilot:
  token: your token

```

### Dynamic Configuration
```yaml
http:
  middlewares:
    my-plugin:
      plugin:
        abtest:
          serviceName: "api"
          redisAddr: "127.0.0.1:6379"
          redisPassword: ""
          redisEnable: true
          redisLoadInterval: 60
          userIdentifyPrefix: ""
          headerAccessToken: "Authorization"
          queryAccessToken: "access_token"
          cookieAccessToken: "access_token"
          headerVersion: "X-Version"
          redisRulesKey: "abtests"
          redisMaxRuleLen: 256
          rules:
            - name: "rule1"
              serviceName: "api"
              enable: true
              desc: "desc"
              priority: 2
              Hosts:
                - http://localhost:8999/r1/beta
                - http://localhost:8999/r1/alpha
                - http://localhost:8999/r1/test
              strategy: match_url
              list:
                - 1
                - 3
              percent: 10
              minVersion: "1.1.1"
              maxversion: "2.2.2"
```