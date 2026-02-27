# ab_core/auth/oauth2/schema/exchange.py
from pydantic import AnyHttpUrl, BaseModel


class OAuth2ExchangeCodeRequest(BaseModel):
    """Request model for exchanging an authorization code for tokens."""

    code: str
    state: str | None = None
    expected_state: str | None = None
    delete_after: bool = True


class PKCEExchangeCodeRequest(OAuth2ExchangeCodeRequest):
    """PKCE-specific exchange request, includes code_verifier."""

    code_verifier: str | None = None


class OAuth2ExchangeFromRedirectUrlRequest(BaseModel):
    """Request model for exchanging an authorization code by parsing a redirect URL."""

    redirect_url: AnyHttpUrl
    enforce_redirect_uri_match: bool = True
    expected_state: str | None = None
    delete_after: bool = True


class PKCEExchangeFromRedirectUrlRequest(OAuth2ExchangeFromRedirectUrlRequest):
    """PKCE-specific exchange from redirect URL, includes code_verifier."""

    code_verifier: str | None = None
