# Binding API Calls

This documentation file contains guidelines in order to interact with the binding entity.

A binding, is a structure that maps various forms of authentication to the credentials of a service type's "user" entity.

For example, a service type's "user", requires an api token to authenticate to its respective service type. This token should be either
 
remembered by the "user" or retrieved using some form of credentials.
 
 A binding will hold additional information like a DN or an OIDC Token(in the auth_identifier field), that can be used to retrieve the required api token.
 
 A binding is associated with the uuid of a service type,the host on which this service type runs on,
 
 It also requires the unique_key that the service type that is associated with, uses in order to expose its "user's" information.
## [POST] Manage Bindings - Create New Binding

This request creates a new binding.

#### Request

```
POST /v1/bindings/{name}`
```

### Example request

```
curl -X POST -H "Content-Type: application/json"
  "https://{URL}/v1/bindings/b1?key={key_in_the_config}"
```

##### Post Body

```
{
	"name": "b1",
	"service_uuid": "b61030d9-bef3-4768-9a03-7b1ff36e8af4cc",
	"host": "host1",
	"auth_identifier":"dn",
	"auth_type": "x509",
	"unique_key": "key"
}
```
 
### Response
 
If the request is successful, the response contains the newly created binding.
 
Success Response
 
`201 CREATED`
 
```
 {
     "name": "b1",
     "service_uuid": "b61030d9-bef3-4768-9a03-7b1ff36e8af4cc",
     "host": "host1",
     "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4cc",
     "auth_identifier": "dn",
     "unique_key": "key",
     "auth_type": "x509",
     "created_on": "2018-05-24T09:58:17Z"
 }
 
```
  
### Errors

Please refer to section [Errors](api_errors.md) to see all possible Errors
  
## [GET] Manage Bindings - List All Bindings

This request lists all bindings that are currently present in th service.
    
### Request
    
```
GET /v1/bindings
```
    
### Response
     
If the request is successful, the response contains all the bindings in the service.
   
#### Success Response
     
`200 OK`
     
```
  {
      "bindings": [
              {
                  "name": "testb",
                  "service_uuid": "uuid1",
                  "host": "host1",
                  "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4cc",
                  "auth_identifier": "testdn",
                  "unique_key": "key",
                  "auth_type": "x509",
                  "created_on": "2018-05-23T09:25:25Z",
                  "last_auth": "2018-05-23T09:25:25Z"
              },
              {
                  "name": "testb2",
                  "service_uuid": "uuid1",
                  "host": "host1",
                  "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4rr",
                  "auth_identifier": "testdn",
                  "unique_key": "key",
                  "auth_type": "x509",                
                  "created_on": "2018-05-23T09:25:43Z",
                  "last_auth": "2018-05-23T09:25:25Z"
              }
      ]
  }
```
  
### Errors
  
Please refer to section [Errors](api_errors.md) to see all possible Errors

## [GET] Manage Bindings - List All Bindings By Service Type And Host

This request returns all the bindings under the specified service type and host.
    
### Request

```
GET /v1/service-types/{service-type}/hosts/{host}/bindings`
```
    
### Response
     
If the request is successful, the response contains all the bindings under the given host and service.
   
#### Success Response
     
`200 OK`
     
```
  {
      "bindings": [
              {
                  "name": "testb",
                  "service_uuid": "uuid1",
                  "host": "host1",
                  "auth_identifier": "testdn",
                  "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4cc",
                  "unique_key": "key",
                  "auth_type": "x509",                
                  "created_on": "2018-05-23T09:25:25Z",
                  "last_auth": "2018-05-23T09:25:25Z"
              },
              {
                  "name": "testb2",
                  "service_uuid": "uuid1",
                  "host": "host1",
                  "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4rr",
                  "auth_identifier": "testdn",
                  "unique_key": "key",
                  "auth_type": "x509",                
                  "created_on": "2018-05-23T09:25:43Z",
                  "last_auth": "2018-05-23T09:25:25Z"
              }
      ]
  }
```
  
### Errors

Please refer to section [Errors](api_errors.md) to see all possible Errors

## [GET] Manage Bindings - List One Binding by Auth identifier

This request returns the binding under the provider service type and host matching
the auth identifier
    
### Request

```
GET /v1/service-types/{service-type}/hosts/{host}/bindings?authID=test_dn
```
    
### Response
     
If the request is successful, the response contains all the bindings under the given host and service.
   
#### Success Response
     
`200 OK`
     
```
  {
      "bindings": [
              {
                  "name": "testb",
                  "service_uuid": "uuid1",
                  "host": "host1",
                  "auth_identifier": "testdn",
                  "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4cc",
                  "unique_key": "key",
                  "auth_type": "x509",                
                  "created_on": "2018-05-23T09:25:25Z",
                  "last_auth": "2018-05-23T09:25:25Z"
              }
      ]
  }
```
  
### Errors

Please refer to section [Errors](api_errors.md) to see all possible Errors

## [GET] Manage Bindings - List One Binding By NAME

This request retrieves the information of a binding associated with the provided name.
    
### Request
    
```
GET /v1/bindings/{name}
```    

### Response     

If the request is successful, the response contains the binding associated with the given uuid
   
#### Success Response
     
`200 OK`
     
```
  {
      "name": "testb",
      "service_uuid": "uuid1",
      "host": "host1",
      "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4cc",
      "auth_identifier": "testdn",
      "unique_key": "key",
      "auth_type": "x509",                
      "created_on": "2018-05-23T09:25:25Z",
      "last_auth": "2018-05-23T09:25:25Z"   
  }
```
  
### Errors

Please refer to section [Errors](api_errors.md) to see all possible Errors


## [PUT] Manage Bindings - Update a Binding

This request updates binding. You can specify one or more fields to update.
The allowed to be updated fields are:

`name, service_uuid, host, auth_identifier, auth_type, unique_key`.

#### Request

```
PUT /v1/bindings/{name}
```

##### Request Body

```
{
	"name": "b1_updated"
}
```
 
### Response
 
If the request is successful, the response contains the updated binding.
 
#### Success Response
 
`200 OK`
 
```
 {
     "name": "b1_updated",
     "service_uuid": "b61030d9-bef3-4768-9a03-7b1ff36e8af4cc",
     "host": "host1",
     "uuid": "p61020d9-bef3-4768-9a03-331ff36e8af4cc",
     "auth_identifier": "host1",
     "unique_key": "key",
     "auth_type": "x509",                
     "created_on": "2018-05-24T09:58:17Z"
 }
```
  
### Errors
Please refer to section [Errors](api_errors.md) to see all possible Errors


## [DELETE] Manage Bindings - Delete a Binding

This request deletes a binding.

#### Request

```
DELETE /v1/bindings/{name}`
```

### Response
 
If the request is successful, the response is empty.
 
#### Success Response
 
`204 No Content`
