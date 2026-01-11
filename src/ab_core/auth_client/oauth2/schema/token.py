from pydantic import BaseModel, SecretStr


class OAuth2Token(BaseModel):
    """An OAuth2 token model with secrets stored as SecretStr."""

    access_token: SecretStr
    id_token: SecretStr | None = None
    refresh_token: SecretStr | None = None
    expires_in: int
    scope: str | None = None
    token_type: str


class OAuth2TokenExposed(BaseModel):
    """An OAuth2 token model with secrets exposed as plain strings."""

    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
