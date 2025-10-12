from pydantic import BaseModel


class OAuth2Token(BaseModel):
    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
    expires_in: int
    scope: str | None = None
    token_type: str
