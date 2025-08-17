# ab_core/auth/oauth2/schema/authorize.py
from typing import Dict, Optional

from pydantic import AnyHttpUrl, BaseModel, Field

from ab_core.pkce.methods import PKCE, S256PKCE

# ---------- Requests ----------


class OAuth2BuildAuthorizeRequest(BaseModel):
    scope: str = "openid profile email"
    response_type: str = "code"
    state: Optional[str] = None
    state_ttl: Optional[int] = None
    extra_params: Optional[Dict[str, str]] = None


class PKCEBuildAuthorizeRequest(OAuth2BuildAuthorizeRequest):
    # If None, the PKCE client will default to S256
    pkce: Optional[PKCE] = Field(
        default_factory=S256PKCE,
    )


# ---------- Responses ----------


class OAuth2AuthorizeResponse(BaseModel):
    url: AnyHttpUrl
    state: str


class PKCEAuthorizeResponse(OAuth2AuthorizeResponse):
    code_verifier: str
    code_challenge: str
    code_challenge_method: str
