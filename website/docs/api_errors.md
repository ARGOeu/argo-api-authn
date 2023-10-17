---
id: api_errors
title: Errors
sidebar_position: 7
---

# Errors

In case of an Error during handling a user’s request, the API responds using the following schema:

```json
{
   "error": {
      "code": 500,
      "message": "Something bad happened",
      "status": "INTERNAL"
   }
}
```
## Error Codes

The following error codes are the possible errors of all methods

Error | Code | Status | Related Requests
------|------|----------|------------------
Invalid JSON | 400 | BAD REQUEST | Create Service (POST)
Not found | 404 | NOT FOUND | List One service(GET)
Service already exists | 409 | CONFLICT | Create Service (POST)
Service Invalid Argument| 422 | UNPROCCESABLE ENTITY| Create Service (POST)
Server Error | 500 | INTERNAL SERVER ERROR| ALL
  