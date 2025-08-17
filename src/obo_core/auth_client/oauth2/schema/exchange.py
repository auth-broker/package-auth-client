# obo_core/auth/oauth2/schema/exchange.py
from pydantic import AnyHttpUrl, BaseModel


class OAuth2ExchangeCodeRequest(BaseModel):
    code: str


class OAuth2ExchangeFromRedirectUrlRequest(BaseModel):
    redirect_url: AnyHttpUrl
    expected_state: str | None = None
    enforce_redirect_uri_match: bool = True


class PKCEExchangeCodeRequest(OAuth2ExchangeCodeRequest):
    code_verifier: str | None = None
    state: str | None = None
    delete_after: bool = True


class PKCEExchangeFromRedirectUrlRequest(OAuth2ExchangeFromRedirectUrlRequest):
    code_verifier: str | None = None
    delete_after: bool = True
