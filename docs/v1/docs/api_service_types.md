# Service API Calls

## [POST] Manage Service Types - Create New Service Type

This request creates a new service type.

#### Request

```
POST /v1/service-types
```

`auth_types:` This field refers to the authentication types that the service type wishes to support.The provided authentication types should also be supported by the authn service. E.g. a service type wishes to use an authentication type of x509 certificate, meaning that it will enable its users to use x509 certificates as an alternative authentication mechanism.The authn service will use an internal handler to map x509 certificates to a service-types credentials, so when declaring an auth-type, it needs to be first, supported b the authn-service itself.


`auth_method`: This field refers to the authentication method that the service type uses in order to authenticate requests against it.The specified authentication method should also be supported by the authn service. E.g. a service type can use the `api-key` authentication method which means that it uses an api key/token to authenticate/authorize requests against it. Each authentication method uses an internal handlers from the authn service in order to be executed, that's why the declared authentication method must be supported.

`retrieval_field`:The field refers to the response's field from the respective service type, which will contain the token we need. E.g. when accessing a service type's users, the response's field that might contain the token we are looking for, might come in different placeholders, like, access_token, token, jwt, etc.
### Example request
```
curl -X POST -H "Content-Type: application/json"
  "https://{URL}/v1/service-types?key={key_in_the_config}"
```


##### Post Body

```
{
 	"name": "string",
 	"hosts": ["host1", "host2"],
 	"auth_types": ["x509", "oidc"],
 	"auth_method": "api-key",
 	"retrieval_field": "token",
 	"type": "ams"
 }
```
 
### Response
 
If the request is successful, the response contains the newly created service type.
 
#### Success Response
 
`201 CREATED`
 
```
 {
  	"name": "string",
  	"hosts": ["host1", "host2"],
  	"auth_types": ["x509", "oidc"],
  	"auth_method": "api-key",
  	"uuid": "da22b2d4-ba6c-43ca-b28d-400cd0a5d83e",
  	"retrieval_field": "token",
  	"type": "ams",
  	"created_on": "2018-05-05T18:04:05Z" 
  }
```
  
### Errors

Please refer to section [Errors](api_errors.md) to see all possible Errors
  
## [GET] Manage Service Types - ListAllServiceTypes
  
### Request
  
```
GET/v1/service-types
```
  
### Response
  
 If the request is successful, the response contains all the service types.
   
#### Success Response
   
`200 OK`
   
```
{
    "service_types": [
        {
            "name": "s1",
            "hosts": [
                "example.gr",
                "127.0.0.1"
            ],
            "auth_types": [
                "x509"
            ],
            "auth_method": "api-key",
            "uuid": "da22b2d4-ba6c-43ca-b28d-400cd0a5d83e",
            "retrieval_field": "token",
            "type": "ams",
            "created_on": ""
        },
        {
            "name": "s2",
            "hosts": [
                "127.0.0.1",
                "example2.gr"
            ],
            "auth_types": [
                "x509",
                "oidc"
            ],
            "auth_method": "api-key",
            "uuid": "da22b2d4-ba6c-43ca-b28d-400sd0a5d83e",
            "retrieval_field": "token",
            "type": "ams",
            "created_on": "2018-05-13T21:52:58Z"
        }
    ]
}
```

### Errors

Please refer to section [Errors](api_errors.md) to see all possible Errors

## [GET] Manage Service Types - ListOneServiceType
  
### Request
  
```
GET/v1/service-types/{NAME}
```
  
If the request is successful, the response contains information for the requested service type.
   
#### Success Response
   
`200 OK`
   
```
   {
    	"name": "string",
    	"hosts": ["host1", "host2"],
    	"auth_types": ["x509", "oidc"],
    	"auth_method": "api-key",
    	"uuid": "da22b2d4-ba6c-43ca-b28d-400cd0a5d83e",
    	"retrieval_field": "token",
    	"type": "ams",
    	"created_on": "2018-05-05T18:04:05Z" 
    }
```

Please refer to section [Errors](api_errors.md) to see all possible Errors

## [PUT] Manage Service Types - Update a Service Type

This request updates a service type. You can specify one or more fields to update.
The allowed to be updated fields are:

`name, hosts, auth_types, auth_method, retrieval_field`.

### Request

```
PUT /v1/service-type/{service-type}
```

#### Request Body

```
{
	"name": "s1_updated"
}
```
 
### Response
 
If the request is successful, the response contains the updated service type.
 
#### Success Response
 
`200 OK`
 
```
 {
    	"name": "s1_updated",
    	"hosts": ["host1", "host2"],
    	"auth_types": ["x509", "oidc"],
    	"auth_method": "api-key",
    	"uuid": "da22b2d4-ba6c-43ca-b28d-400cd0a5d83e",
    	"retrieval_field": "token",
    	"type": "ams",
    	"created_on": "2018-05-05T18:04:05Z" 
 }
```
  
### Errors
Please refer to section [Errors](api_errors.md) to see all possible Errors