# ab_core/auth/oauth2/schema/authorize.py

from pydantic import AnyHttpUrl, BaseModel, Field, Literal

from ab_core.pkce.methods import PKCE, S256PKCE

from .client_type import OAuth2ClientType

# ---------- Requests ----------


class OAuth2BuildAuthorizeRequest(BaseModel):
    type: Literal[OAuth2ClientType.STANDARD] = OAuth2ClientType.STANDARD
    scope: str = "openid profile email"
    response_type: str = "code"
    state: str | None = None
    state_ttl: int | None = None
    extra_params: dict[str, str] | None = None


class PKCEBuildAuthorizeRequest(OAuth2BuildAuthorizeRequest):
    type: Literal[OAuth2ClientType.PKCE] = OAuth2ClientType.PKCE
    # If None, the PKCE client will default to S256
    pkce: PKCE | None = Field(
        default_factory=S256PKCE,
    )


AuthorizeRequest = Annotated[
    OAuth2BuildAuthorizeRequest | PKCEBuildAuthorizeRequest,
    Field(discriminator="type"),
]


# ---------- Responses ----------


class OAuth2AuthorizeResponse(BaseModel):
    type: Literal[OAuth2ClientType.STANDARD] = OAuth2ClientType.STANDARD
    url: AnyHttpUrl
    state: str


class PKCEAuthorizeResponse(OAuth2AuthorizeResponse):
    type: Literal[OAuth2ClientType.PKCE] = OAuth2ClientType.PKCE
    code_verifier: str
    code_challenge: str
    code_challenge_method: str


AuthorizeResponse = Annotated[
    OAuth2AuthorizeResponse | PKCEAuthorizeResponse,
    Field(discriminator="type"),
]
