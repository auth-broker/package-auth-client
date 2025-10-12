from pydantic import BaseModel, SecretStr


class OAuth2Token(BaseModel):
    access_token: SecretStr
    id_token: SecretStr | None = None
    refresh_token: SecretStr | None = None
    expires_in: int
    scope: str | None = None
    token_type: str
