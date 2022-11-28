---
id: api_version
title: Version
sidebar_position: 5
---

# Version API Call

## [GET] Version API Call

This request retrieves information about the service build, environment, etc.

**NOTE** In order to also retrieve the `release` field you need to perform
an authorised request otherwise the api call requires no auth token.
#### Request

```
GET /v1/version
```

### Example request

```
curl -X GET -H "Content-Type: application/json"
"https://{URL}/v1/version?key={key_in_the_config}"
```


### Response

If the request is successful, the response contains the
service version info.

Success Response

`200 OK`

```
{
    "build_time": "2022-10-10T13:21:07Z",
    "golang": "go1.14",
    "compiler": "gc",
    "os": "linux",
    "architecture": "amd64",
    "release": "1.0.0",
    "distro": "CentOS Linux release 7.9.2009 (Core)",
}
 
```

### Errors
Please refer to section [Errors](api_errors.md) to see all possible Errors
