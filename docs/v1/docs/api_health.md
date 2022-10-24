# Health API Call

## [GET] Health API Call

This request returns whether the service is running or not.

#### Request

```
GET /v1/health
```

### Example request

```
curl -X GET "https://{URL}/v1/health"
```


### Response

If the request is successful, the response contains a 200 code.

Success Response

`200 OK`


### Errors
Please refer to section [Errors](api_errors.md) to see all possible Errors
