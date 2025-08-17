from typing import Optional

from pydantic import BaseModel


class OAuth2Token(BaseModel):
    access_token: str
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_in: int
    scope: Optional[str] = None
    token_type: str
