# fastapi-cognito-security

A micro-library that implements a [FastAPI security](https://github.com/tiangolo/fastapi/blob/master/fastapi/security/base.py) class for [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html) security.

This library supports receiving the Cogntio access (recommended) or id token in the HTTP `Authorization`
header using the standard `Bearer` mechansism (e.g. - `Authorization: Bearer <token>`).

## Installation
```bash
pip install fastapi-cognito-security
```

## Usage

### Securing an individual route
```python
from fastapi import Depends, FastAPI
from fastapi_cognito_security import CognitoBearer

app = FastAPI()
auth = CognitoBearer(
    app_client_id="my_app_client_id",
    userpool_id="my_userpool_id"
)

@app.get("/", dependencies=[Depends(auth)])
async def root():
    return {"message": "Hello World"}
```

### Securing a whole api
```python
from fastapi import Depends, FastAPI
from fastapi_cognito_security import CognitoBearer

auth = CognitoBearer(
    app_client_id="my_app_client_id",
    userpool_id="my_userpool_id"
)
app = FastAPI(dependencies=[Depends(auth)])

@app.get("/")
async def root():
    return {"message": "Hello World"}
```

When called, the `CognitoBearer` object will:
1. Get the public keys from your AWS Cognito UserPool.
    > NOTE - this will only happen once, and will be cached thereafter.
2. Validate the JWT by verifying:
    1. The JWT is correctly constructed and conforms to the public key.
    2. The JWT has not expired.
    3. The `client_id` (access token) or `aud` (id token) matches the `app_client_id`.
3. Return either a `fastapi_cognito_security.AccessToken` or `fastapi_cognito_security.IdToken` that contains the claims.
    > NOTE - you can use these claims for further verification either within your API or by subclassing `CognitoBearer`.

Any failure in the above steps will result in a `fastapi.HTTPException` being raised.

## Claims
The returned `AccessToken` or `IdToken` will have the standard Cognito claims converted to Python types.

### `AccessToken` and `IdToken`
|Claim|Python Type|
|--|--|
|auth_time|datetime.datetime|
|exp|datetime.datetime|
|iat|datetime.datetime|
|iss|pydantic.HttpUrl|
|jti|uuid.UUID|
|origin_jti|uuid.UUID|
|sub|uuid.UUID|

- Username (`username` in access tokens and `cognito:username` in id tokens) is canonicalized to the claim `username`.
- All additional claims will be converted directly to basic Python types. 
- All claim names will have `:` replaced with `_` (e.g. - `custom:thing` will become `custom_thing`)

### `AccessToken` only
|Claim|Python Type|
|--|--|
|device_key|uuid.UUID|
|scope|list[str]|

## Swagger/OpenAPI 3.0 Support
Because `CognitoBearer` is a `fastapi.HTTPBearer`, it will operate in the docs that are auotmatically
generated by FastAPI in the same way as it's parent class.
