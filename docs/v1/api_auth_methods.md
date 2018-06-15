  # Auth method API Calls

## [POST] Manage Auth Methods - Create New Auth Method

This request creates a new service.

#### Request

`POST /v1/authM`

### Example request
```
curl -X POST -H "Content-Type: application/json"
  "https://{URL}/v1/authM?key={key_in_the_config}"
```


##### Post Body

```json
        {
            "access_key": "key1",
            "host": "127.0.0.1",
            "path": "/path/{{identifier}}?key={{access_key}}",
            "port": 9000,
            "service_uuid1": "da22b2d4-ba6c-43ca-b28d-400sd0a5d83e",
            "type": "api-key"
        }
 ```
 
  ### Response
  
  If the request is successful, the response contains the newly created auth method.
  
  Success Response
  
  `201 CREATED`
  
  ```json
        {
            "access_key": "key1",
            "host": "127.0.0.1",
            "path": "/path/{{identifier}}?key={{access_key}}",
            "port": 9000,
            "service_uuid": "da22b2d4-ba6c-43ca-b28d-400sd0a5d83e",
            "type": "api-key"
        }
   ```
 
  ## [GET] Manage Auth Methods - ListOneAuthMethod
  
  ### Request
  
  `GET /v1/services/{service}/hosts/{host}/authM`
  
  ### Example request
  ```
  curl -X GET -H "Content-Type: application/json"
  "https://{URL}/v1/services/{service}/hosts/{host}/authM?key={key_in_the_config}"
  ```
  
   If the request is successful, the response contains information for the requested auth method.
   
   Success Response
   
   `200 OK`
   
```json
{
    "access_key": "key1",
    "host": "127.0.0.1",
    "path": "/v1/users:byUUID/{{identifier}}?key={{access_key}}",
    "port": 8081,
    "service_uuid": "da22b2d4-ba6c-43ca-b28d-400sd0a5d83e",
    "type": "api-key"
}
```


  ## [GET] Manage Auth Methods - ListAllAuthMethods
  
  ### Request
  
  `GET /v1/authM`
  
  ### Example request
  ```
  curl -X GET -H "Content-Type: application/json"
  "https://{URL}/v1/authM?key={key_in_the_config}"
  ```
  
   If the request is successful, the response contains information for all the auth methods.
   
   Success Response
   
   `200 OK`
   
```json
{
  "auth_methods": [
    {
      "access_key": "key",
      "host": "host2",
      "path": "path",
      "port": 9000,
      "service_uuid": "da22b2d4-ba6c-43ca-b28d-400sd0a5d83e",
      "type": "api-key"
    },
    {
      "access_key": "key",
      "host": "host1",
      "path": "path",
      "port": 9000,
      "service_uuid": "da22b2d4-ba6c-43ca-b28d-400sd0a5d83a",
      "type": "api-key"
    }
  ]
}
```
  Please refer to section [Errors](api_errors.md) to see all possible Errors
  
  ## [DELETE] Manage Auth Methods - Delete an auth method
  
  This request deletes an auth method associated with the provided service-type and host.
  
  #### Request
  
  `DELETE /v1/service-types/{service-type}/hosts/{host}/authM`
  
   ### Response
   
   If the request is successful, the response is empty.
   
   Success Response
   
   `204 No Content`