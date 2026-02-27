# ab_core/auth/oauth2/schema/authorize.py

from typing import Annotated, Literal

from pydantic import AnyHttpUrl, BaseModel, Field

from ab_core.pkce.methods import PKCE, S256PKCE

from .client_type import OAuth2ClientType

# ---------- Requests ----------


class OAuth2BuildAuthorizeRequest(BaseModel):
    type: Literal[OAuth2ClientType.STANDARD] = OAuth2ClientType.STANDARD
    scope: str = "openid profile email"
    response_type: str = "code"
    state: str | None = Field(
        default=None,
        description="Custom state value to correlate the request and response. If not provided, a random state will be generated."
        " Be careful when setting this to a static value in production - it should be unique per request to prevent CSRF attacks."
        " If you provide your own state, you should also handle persistence and verification of the state value in the callback.",
    )
    state_ttl: int = Field(
        default=600,
        description="Time-to-live for the state in seconds."
        " Only applicable a cache session is used. Defaults to 600 seconds (10 minutes) if not specified.",
    )
    extra_params: dict[str, str] | None = Field(
        default=None,
        description="Extra query parameters to include in the authorize URL."
        " Can be used to pass through an identity provider hint (e.g. `idp=Google`) or other custom params your IdP may support.",
    )
    app_context: dict[str, str] | None = Field(
        default=None,
        description="Custom context about the app or request to pass through the auth flow."
        " Not sent to the IdP, but is persisted in cache and accessed in later steps (e.g. token exchange) keyed by state.",
    )


class PKCEBuildAuthorizeRequest(OAuth2BuildAuthorizeRequest):
    type: Literal[OAuth2ClientType.PKCE] = OAuth2ClientType.PKCE
    # If None, the PKCE client will default to S256
    pkce: PKCE | None = Field(
        default_factory=S256PKCE,
    )


BuildAuthorizeRequest = Annotated[
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
