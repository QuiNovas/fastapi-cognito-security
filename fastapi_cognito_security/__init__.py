from datetime import datetime
from functools import partial
from typing import Any, Optional
from uuid import UUID

from cognitojwt import CognitoJWTException, decode_async
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel, Extra, HttpUrl, root_validator, validator


class CognitoToken(BaseModel):
    auth_time: datetime
    exp: datetime
    iat: datetime
    iss: HttpUrl
    jti: UUID
    origin_jti: UUID
    sub: UUID
    username: str


class AccessToken(CognitoToken, extra=Extra.allow):
    client_id: str
    device_key: Optional[UUID]
    scope: Optional[list[str]]

    @validator("scope", pre=True)
    def split_scopes(cls, value: str) -> list[str]:
        return value.split()

    @root_validator(pre=True)
    def conform_token(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values.pop("token_use", None) != "access":
            raise ValueError("Not an access token")
        return {key.replace(":", "_"): value for key, value in values.items()}


class IdToken(CognitoToken, extra=Extra.allow):
    aud: str

    @root_validator(pre=True)
    def conform_token(cls, values: dict[str, Any]) -> dict[str, Any]:
        if values.pop("token_use", None) != "id":
            raise ValueError("Not an id token")
        values["username"] = values.pop("cognito:username")
        return {key.replace(":", "_"): value for key, value in values.items()}


TOKEN_CLS = dict(access=AccessToken, id=IdToken)


class CognitoBearer(HTTPBearer):
    def __init__(
        self,
        *,
        app_client_id: str,
        userpool_id: str,
        description: str = None,
    ) -> None:
        super().__init__(description=description)
        self.__decode_async = partial(
            decode_async,
            app_client_id=app_client_id,
            region=userpool_id.split("_")[0],
            userpool_id=userpool_id,
        )

    async def __call__(self, request: Request) -> CognitoToken:
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)
        try:
            token = await self.__decode_async(token=credentials.credentials)
            return TOKEN_CLS[token["token_use"]](**token)
        except (JWTError, KeyError, ValueError) as e:
            raise HTTPException(
                status_code=400,
                detail="Malformed Authentication token",
            ) from e
        except CognitoJWTException as cje:
            raise HTTPException(status_code=401, detail=str(cje)) from cje
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e)) from e
