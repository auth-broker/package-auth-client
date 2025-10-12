from pydantic import BaseModel, SecretStr


class RefreshTokenRequest(BaseModel):
    refresh_token: SecretStr
    scope: str | None = None  # optional; most providers ignore if omitted
