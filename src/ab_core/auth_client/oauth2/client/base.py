from abc import ABC, abstractmethod
from typing import (
    Any,
    Generic,
    TypeVar,
)
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
from ab_core.auth_client.oauth2.schema.refresh import RefreshTokenRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.cache.caches.base import CacheAsyncSession, CacheSession

BuildReqT = TypeVar("BuildReqT", bound=OAuth2BuildAuthorizeRequest)
BuildResT = TypeVar("BuildResT", bound=OAuth2AuthorizeResponse)
ExReqT = TypeVar("ExReqT", bound=OAuth2ExchangeCodeRequest)
ExUrlReqT = TypeVar("ExUrlReqT", bound=OAuth2ExchangeFromRedirectUrlRequest)


class OAuth2ClientBase(BaseModel, ABC, Generic[BuildReqT, BuildResT, ExReqT, ExUrlReqT]):
    config: OIDCConfig = Field(..., description="OIDC client configuration")

    @abstractmethod
    def get_state_cache_key(self, state: str) -> str: ...

    # ---------- Authorize URL ----------
    @abstractmethod
    def build_authorize_request(
        self,
        request: BuildReqT,
        *,
        cache_session: CacheSession | None = None,  # separate param
    ) -> BuildResT: ...

    @abstractmethod
    async def build_authorize_request_async(
        self,
        request: BuildReqT,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> BuildResT: ...

    # ---------- Exchanges ----------
    @abstractmethod
    def exchange_code(
        self,
        request: ExReqT,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token: ...

    @abstractmethod
    async def exchange_code_async(
        self,
        request: ExReqT,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token: ...

    @abstractmethod
    def exchange_from_redirect_url(
        self,
        request: ExUrlReqT,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token: ...

    @abstractmethod
    async def exchange_from_redirect_url_async(
        self,
        request: ExUrlReqT,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token: ...

    @abstractmethod
    def refresh(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token: ...

    @abstractmethod
    async def refresh_async(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token: ...

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
                f"Redirect URL `{redirect_url}` does not match configured redirect_uri `{self.config.redirect_uri}`"
            )

    def _pop_state(
        self,
        *,
        state: str,
        keys: list[str] | tuple[str, ...],
        delete_after: bool = True,
        cache_session: CacheSession,
    ) -> tuple[Any, ...]:
        cache_key = self.get_state_cache_key(state)
        cache_value = cache_session.get(cache_key)
        if cache_value is None:
            raise ValueError("state not found in cache for given state")
        values = []
        for key in keys:
            values.append(cache_value.get(key))
        if delete_after:
            cache_session.delete(cache_key)
        return tuple(values)

    async def _pop_state_async(
        self,
        *,
        state: str,
        keys: list[str] | tuple[str, ...],
        delete_after: bool = True,
        cache_session: CacheAsyncSession,
    ) -> tuple[Any, ...]:
        cache_key = self.get_state_cache_key(state)
        cache_value = await cache_session.get(cache_key)
        if cache_value is None:
            raise ValueError("state not found in cache for given state")
        values = []
        for key in keys:
            values.append(cache_value.get(key))
        if delete_after:
            await cache_session.delete(cache_key)
        return tuple(values)

    def _save_state(
        self,
        *,
        state: str,
        value: dict,
        expiry: int | None = None,
        cache_session: CacheSession,
    ) -> None:
        cache_key = self.get_state_cache_key(state)
        cache_session.set(key=cache_key, value=value, expiry=expiry)

    async def _save_state_async(
        self,
        *,
        state: str,
        value: dict,
        expiry: int | None = None,
        cache_session: CacheAsyncSession,
    ) -> None:
        cache_key = self.get_state_cache_key(state)
        await cache_session.set(key=cache_key, value=value, expiry=expiry)
