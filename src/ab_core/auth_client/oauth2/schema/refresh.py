from pydantic import BaseModel


class RefreshTokenRequest(BaseModel):
    refresh_token: str
    scope: str | None = None  # optional; most providers ignore if omitted
