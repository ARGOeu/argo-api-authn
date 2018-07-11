# Auth method API Calls

## [POST] Manage Auth Methods - Create New Auth Method

This request creates a new auth method for the given service type. The type of the auth method
as well as some of its predefined fields will be decided by the service-tye's `auth_method` and `type `fields.
E.g. for a service-type of type `ams` with an auth_method of type `api-key`, it will create an api-key auth method
with predeclared fields for `path` and `retrieval_field` that are common across all type `ams` service-types.
Of course you can always override the default's if you like. 

#### Fields

- path: Combined with the `host` and the `port` is represents the URL where the external resource is located. We use it to map the x509 certificate or any other auth mechanism to the needed token
- access_key: In the case of an api-key method, the access key specifies te `key` to use in order to access the external resource
- retrieval_field: The response field from the external service that will contain the attribute we are looking for. e.g. `token`

### Request

```
POST /v1/service-types/{Name}/authm`
```


### Example request
```
curl -X POST -H "Content-Type: application/json"
  "https://{URL}/v1/service-types/{Name}/authm?key={key_in_the_config}"
```

### Post Body

```
        {
            "access_key": "key1",
            "host": "127.0.0.1",
            "port": 9000,
        }
```
 
### Response
  
If the request is successful, the response contains the newly created auth method.
  
Success Response
  
`201 CREATED`
  
```
        {
            "access_key": "key1",
            "host": "127.0.0.1",
            "service_uuid": "da22b2d4-ba6c-43ca-b28d-400sd0a5d83e",
            "path": "/path/{{identifier}}?key={{access_key}}",
            "port": 9000,
            "retrieval_field": "token",
            "type": "api-key",
            "uuid": "da22b2d4-8ip0-43ca-b28d-500sd0a5d876e",
            "created_on": "2018-05-05T18:04:05Z"
        }
```

Please refer to section [Errors](api_errors.md) to see all possible Errors

