# cert-welder

a tool to build/show certificate chains from a collection of certificates.

## usage

```
$ go get -u github.com/amlweems/cert-welder
$ cd some-file-system/
$ cert-welder
[CN=dns-tls-ca]
  env/1/dns/config/certs/api/client_ca.crt
  env/1/dns/config/certs/api/server_ca.crt
  env/1/dns/config/certs/health/client_ca.crt
  env/1/dns/config/certs/health/server_ca.crt
  env/2/dns/config/certs/api/client_ca.crt
  env/2/dns/config/certs/api/server_ca.crt
  env/2/dns/config/certs/health/client_ca.crt
  env/2/dns/config/certs/health/server_ca.crt
    [CN=health.dns]
      env/1/dns/config/certs/health/server.crt
      env/2/dns/config/certs/health/server.crt
    [CN=health.dns]
      env/1/dns/config/certs/health/client.crt
      env/2/dns/config/certs/health/client.crt
    [CN=api.dns]
      env/1/dns/config/certs/api/server.crt
      env/2/dns/config/certs/api/server.crt
    [CN=api.dns]
      env/1/dns/config/certs/api/client.crt
      env/2/dns/config/certs/api/client.crt
```
