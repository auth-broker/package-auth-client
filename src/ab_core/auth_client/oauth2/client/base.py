from abc import ABC, abstractmethod
from typing import Generic, Optional, TypeVar
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field

from ab_core.auth_client.oauth2.schema.authorize import (
    OAuth2AuthorizeResponse,
    OAuth2BuildAuthorizeRequest,
)
from ab_core.auth_client.oauth2.schema.exchange import (
    OAuth2ExchangeCodeRequest,
    OAuth2ExchangeFromRedirectUrlRequest,
)
from ab_core.auth_client.oauth2.schema.oidc import OIDCConfig
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.cache.caches.base import CacheSession

BuildReqT = TypeVar("BuildReqT", bound=OAuth2BuildAuthorizeRequest)
BuildResT = TypeVar("BuildResT", bound=OAuth2AuthorizeResponse)
ExReqT = TypeVar("ExReqT", bound=OAuth2ExchangeCodeRequest)
ExUrlReqT = TypeVar("ExUrlReqT", bound=OAuth2ExchangeFromRedirectUrlRequest)


class OAuth2ClientBase(BaseModel, ABC, Generic[BuildReqT, BuildResT, ExReqT, ExUrlReqT]):
    config: OIDCConfig = Field(..., description="OIDC client configuration")

    # ---------- Authorize URL ----------
    @abstractmethod
    def build_authorize_request(
        self,
        request: BuildReqT,
        *,
        cache_session: CacheSession | None = None,  # separate param
        state_ttl: Optional[int] = 600,  # separate param
    ) -> BuildResT: ...

    # ---------- Exchanges ----------
    @abstractmethod
    def exchange_code(self, request: ExReqT) -> OAuth2Token: ...

    @abstractmethod
    def exchange_from_redirect_url(self, request: ExUrlReqT) -> OAuth2Token: ...

    # ---------- Helpers ----------
    def _parse_code_and_state_from_redirect(self, redirect_url: str) -> tuple[str, str | None]:
        p = urlparse(redirect_url)
        qs = parse_qs(p.query)
        code_list = qs.get("code")
        if not code_list or not code_list[0]:
            raise ValueError("No `code` found in redirect URL")
        state = (qs.get("state") or [None])[0]
        return code_list[0], state

    def _validate_redirect_uri_match(self, redirect_url: str) -> None:
        rp = urlparse(redirect_url)
        cp = urlparse(str(self.config.redirect_uri))
        if (rp.scheme, rp.netloc, rp.path) != (cp.scheme, cp.netloc, cp.path):
            raise ValueError(
                f"Redirect URL `{redirect_url}` does not match configured"
                f" redirect_uri `{self.config.redirect_uri}`"
            )
