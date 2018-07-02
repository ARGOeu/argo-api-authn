# Argo Api Authn

<img src="https://jenkins.argo.grnet.gr/static/3c75a153/images/headshot.png" alt="Jenkins" width="25"/> [![Build Status](https://jenkins.argo.grnet.gr/job/argo-api-authn_devel/badge/icon)](https://jenkins.argo.grnet.gr/job/argo-api-authn_devel)

Authentication Service for ARGO API(s)


## Description

The purpose of the Authentication Service is to provide the ability to different services to use alternative authentication mechanisms without having to store additional user info or implement new functionalities.The AUTH service holds various information about a service’s users, hosts, API urls, etc, and leverages them to provide its functionality. 

## Perquisites

Before you start, you need to issue a valid certificate.

## Set Up

1. Install Golang 1.10
2. Create a new work space:

      `mkdir ~/go-workspace`
      
      `export GOPATH=~/go-workspace`
      
      `export PATH=$PATH:$GOPATH/bin`

     You may add the last `export` line into the `~/.bashrc`, `/.zshrc` or the `~/.bash_profile` file to have `GOPATH` environment variable properly setup upon every login.

3. Get the latest version

      `go get github.com/ARGOeu/argo-api-authn`

4. Get dependencies(If you plan on contributing to the project else skip this step):

   Argo-api-authN uses the dep tool for dependency handling.
    
    - Install the dep tool. You can find instructions depending on your platform at [Dep](https://github.com/golang/dep).

5. To build the service use the following command:

      `go build`

6. To run the service use the following command:

      `./argo-api-authn` (This assumes that there is a valid configuration file at `/etc/argo-api-authn/conf.d/argo-api-authn-config.json`).
      
      Else
      
      `./argo-api-authn --config /path/to/a/json/config/file`

7. To run the unit-tests:

    Inside the project's folder issue the command:

      `go test $(go list ./... | grep -v /vendor/)`
 
 8. Install mongoDB
 
 
 ## Configuration
 
 The service depends on a configuration file in order to be able to run.This file contains the following information:
 
 ```json
 {
   "service_port":8080,
   "mongo_host":"mongo_host",
   "mongo_db":"mongo database",
   "certificate_authorities":"/path/to/cas/certificates/",
   "certificate":"/path/to/cert/localhost.crt",
   "certificate_key":"/path/to/key/localhost.key",
   "service_token": "some-token",
   "supported_auth_types": ["x509", "oidc"],
   "supported_auth_methods": ["api-key", "x-api-token"],
   "supported_service_types": ["ams", "web-api"],
   "verify_ssl": true
 }
 ```
 
 ## Important Notes
It is important to notice that since we need to verify the provided certificate’s hostname, 
the client has to make sure that both Forward and  Reverse DNS lookup on the client is correctly setup 
and that the hostname  corresponds to the certificate used.  For both IPv4 and IPv6  (if used) 
 
 ### Common errors
 - Executing a request using IPv6 without having a properly configured reverse DNS.
 ```json
 {
 "error": {
  "message": "lookup *.*.*.*.*.*..... .ip6.arpa. on <ip from where the client executed the request>: no such host",
  "code": 400,
  "status": "BAD REQUEST"
   }
 }
```
- Executing a request from a host that is not registered on the certificate.

A common case for this error is to have the FQDN registered on the certificate 
but a reverse dns look up returns another hostname for the client from where the request was executed. 
```json
{
 "error": {
  "message": "x509: certificate is valid for host1, host2, not host3.",
  "code": 403,
  "status": "ACCESS_FORBIDDEN"
 }
}
```
 ## Helpful Utilities
 You can find various utility scripts to help you get up and running the service inside the
 repo's `bin` folder. You can also find the respective documentation for the scripts inside the `docs` folder.
