import base64
import logging
import secrets
from typing import Literal, override

import httpx
import requests
from yarl import URL

from ab_core.auth_client.oauth2.schema.authorize import (
    PKCEAuthorizeResponse,
    PKCEBuildAuthorizeRequest,
)
from ab_core.auth_client.oauth2.schema.client_type import OAuth2ClientType
from ab_core.auth_client.oauth2.schema.exchange import (
    PKCEExchangeCodeRequest,
    PKCEExchangeFromRedirectUrlRequest,
)
from ab_core.auth_client.oauth2.schema.refresh import RefreshTokenRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.cache.caches.base import CacheAsyncSession, CacheSession

from .base import OAuth2ClientBase

logger = logging.getLogger(__name__)


class PKCEOAuth2Client(
    OAuth2ClientBase[
        PKCEBuildAuthorizeRequest,
        PKCEAuthorizeResponse,
        PKCEExchangeCodeRequest,
        PKCEExchangeFromRedirectUrlRequest,
    ]
):
    type: Literal[OAuth2ClientType.PKCE] = OAuth2ClientType.PKCE

    def get_state_cache_key(self, state: str) -> str:
        return f"{self.type}:{state}"

    @override
    def build_authorize_request(
        self,
        request: PKCEBuildAuthorizeRequest,
        *,
        cache_session: CacheSession | None = None,  # separate param (not in request)
    ) -> PKCEAuthorizeResponse:
        # Base builds URL + state
        state = request.state or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")

        q: dict[str, str] = {
            "response_type": request.response_type,
            "client_id": self.config.client_id,
            "redirect_uri": str(self.config.redirect_uri),
            "scope": request.scope,
            "state": state,
            "code_challenge": request.pkce.challenge,
            "code_challenge_method": request.pkce.method.value,
        }
        if request.extra_params:
            q.update({k: str(v) for k, v in request.extra_params.items()})

        url = str(URL(str(self.config.authorize_url)).with_query(q))

        res = PKCEAuthorizeResponse(
            url=url,
            state=state,
            code_verifier=request.pkce.verifier,
            code_challenge=request.pkce.challenge,
            code_challenge_method=request.pkce.method.value,
        )

        # Persist verifier keyed by state if cache available
        if cache_session is not None:
            self._save_state(
                state=res.state,
                value={
                    "verifier": res.code_verifier,
                    "app_context": request.app_context,
                },
                expiry=request.state_ttl,
                cache_session=cache_session,
            )

        return res

    @override
    async def build_authorize_request_async(
        self,
        request: PKCEBuildAuthorizeRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> PKCEAuthorizeResponse:
        state = request.state or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")

        q: dict[str, str] = {
            "response_type": request.response_type,
            "client_id": self.config.client_id,
            "redirect_uri": str(self.config.redirect_uri),
            "scope": request.scope,
            "state": state,
            "code_challenge": request.pkce.challenge,
            "code_challenge_method": request.pkce.method.value,
        }
        if request.extra_params:
            q.update({k: str(v) for k, v in request.extra_params.items()})

        url = str(URL(str(self.config.authorize_url)).with_query(q))

        res = PKCEAuthorizeResponse(
            url=url,
            state=state,
            code_verifier=request.pkce.verifier,
            code_challenge=request.pkce.challenge,
            code_challenge_method=request.pkce.method.value,
        )

        if cache_session is not None:
            await self._save_state_async(
                state=res.state,
                value={
                    "verifier": res.code_verifier,
                    "app_context": request.app_context,
                },
                expiry=request.state_ttl,
                cache_session=cache_session,
            )

        return res

    # ---- exchanges ----
    def _resolve_verifier_and_app_context(
        self,
        *,
        state: str | None = None,
        code_verifier: str | None,
        delete_after: bool = True,
        cache_session: CacheSession | None = None,
    ) -> tuple[str, dict[str, str] | None]:
        """Resolve PKCE code_verifier and app_context.
        - If provided_verifier is present: use it.
        - If not, require state and load verifier from cache.
        - If state is present, also load app_context from cache (even if verifier was provided),
          unless cache_session is None.
        """
        app_context = None

        # If no verifier provided, must resolve from cache using state
        if code_verifier is None:
            if cache_session is None:
                raise ValueError("Cache session required to resolve code_verifier from state, but not provided")
            if not state:
                raise ValueError("state required to resolve code_verifier from cache, but not provided")
            code_verifier, app_context = self._pop_state(
                state=state,
                keys=["verifier", "app_context"],
                delete_after=delete_after,
                cache_session=cache_session,
            )

        # If verifier was provided, we can still optionally load app_context from cache if state and cache_session are available
        else:
            if cache_session is None:
                logger.warning("Cache session not provided; app_context will not be loaded from cache")
            else:
                if not state:
                    raise ValueError("state required to load app_context from cache, but not provided")
                (app_context,) = self._pop_state(
                    state=state,
                    keys=["app_context"],
                    delete_after=delete_after,
                    cache_session=cache_session,
                )

        # verifier is required for PKCE flows
        if not code_verifier:
            raise ValueError("code_verifier not found in cache for given state")

        return code_verifier, app_context

    async def _resolve_verifier_and_app_context_async(
        self,
        *,
        state: str | None = None,
        code_verifier: str | None,
        delete_after: bool = True,
        cache_session: CacheAsyncSession | None = None,
    ) -> tuple[str, dict[str, str] | None]:
        """Resolve PKCE code_verifier and app_context.
        - If code_verifier is present: use it.
        - If not, require state and load verifier from cache.
        - If state is present, also load app_context from cache (even if verifier was provided),
        unless cache_session is None.
        """
        app_context = None

        # If no verifier provided, must resolve from cache using state
        if code_verifier is None:
            if cache_session is None:
                raise ValueError("Cache session required to resolve code_verifier from state, but not provided")
            if not state:
                raise ValueError("state required to resolve code_verifier from cache, but not provided")
            code_verifier, app_context = await self._pop_state_async(
                state=state,
                keys=["verifier", "app_context"],
                delete_after=delete_after,
                cache_session=cache_session,
            )

        # If verifier was provided, we can still optionally load app_context from cache if state and cache_session are available
        else:
            if cache_session is None:
                logger.warning("Cache session not provided; app_context will not be loaded from cache")
            else:
                if not state:
                    raise ValueError("state required to load app_context from cache, but not provided")
                (app_context,) = await self._pop_state_async(
                    state=state,
                    keys=["app_context"],
                    delete_after=delete_after,
                    cache_session=cache_session,
                )

        # verifier is required for PKCE flows
        if not code_verifier:
            raise ValueError("code_verifier not found in cache for given state")

        return code_verifier, app_context

    @override
    def exchange_code(
        self,
        request: PKCEExchangeCodeRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token:
        code_verifier, app_context = self._resolve_verifier_and_app_context(
            state=request.state,
            code_verifier=request.code_verifier,
            delete_after=request.delete_after,
            cache_session=cache_session,
        )

        payload = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": str(self.config.redirect_uri),
            "code": request.code,
            "code_verifier": code_verifier,
        }
        resp = requests.post(
            self.config.token_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return OAuth2Token.model_validate(
            {
                **resp.json(),
                "app_context": app_context,
            }
        )

    @override
    async def exchange_code_async(
        self,
        request: PKCEExchangeCodeRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token:
        code_verifier, app_context = await self._resolve_verifier_and_app_context_async(
            state=request.state,
            code_verifier=request.code_verifier,
            delete_after=request.delete_after,
            cache_session=cache_session,
        )

        # verifier is required for PKCE flows
        if not code_verifier:
            raise ValueError("code_verifier not found in cache for given state")

        payload = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": str(self.config.redirect_uri),
            "code": request.code,
            "code_verifier": code_verifier,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                str(self.config.token_url),
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
        resp.raise_for_status()
        return OAuth2Token.model_validate(
            {
                **resp.json(),
                "app_context": app_context,
            }
        )

    @override
    def exchange_from_redirect_url(
        self,
        request: PKCEExchangeFromRedirectUrlRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token:
        redirect_url = str(request.redirect_url)
        if request.enforce_redirect_uri_match:
            self._validate_redirect_uri_match(redirect_url)

        code, state = self._parse_code_and_state_from_redirect(redirect_url)
        if request.expected_state is not None and state != request.expected_state:
            raise ValueError("state mismatch")

        return self.exchange_code(
            request=PKCEExchangeCodeRequest(
                code=code,
                state=state,
                expected_state=request.expected_state,
                delete_after=request.delete_after,
                code_verifier=request.code_verifier,
            ),
            cache_session=cache_session,
        )

    @override
    async def exchange_from_redirect_url_async(
        self,
        request: PKCEExchangeFromRedirectUrlRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token:
        redirect_url = str(request.redirect_url)
        if request.enforce_redirect_uri_match:
            self._validate_redirect_uri_match(redirect_url)

        code, state = self._parse_code_and_state_from_redirect(redirect_url)
        if request.expected_state is not None and state != request.expected_state:
            raise ValueError("state mismatch")

        return await self.exchange_code_async(
            request=PKCEExchangeCodeRequest(
                code=code,
                state=state,
                expected_state=request.expected_state,
                delete_after=request.delete_after,
                code_verifier=request.code_verifier,
            ),
            cache_session=cache_session,
        )

    @override
    def refresh(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheSession | None = None,  # kept for symmetry
    ) -> OAuth2Token:
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "refresh_token": request.refresh_token,
        }
        if request.scope:
            payload["scope"] = request.scope

        resp = requests.post(
            self.config.token_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()

        # Some IdPs (e.g. Cognito) rotate refresh tokens; keep the new one if present.
        if "refresh_token" not in data:
            data["refresh_token"] = request.refresh_token

        data["app_context"] = (
            None  # oauth2 flow doesn't have app_context at refresh time, but keep the field for consistency
        )

        return OAuth2Token.model_validate(data)

    async def refresh_async(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token:
        payload = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "refresh_token": request.refresh_token,
        }
        if request.scope:
            payload["scope"] = request.scope

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                str(self.config.token_url),
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
        resp.raise_for_status()
        data = resp.json()

        if "refresh_token" not in data:
            data["refresh_token"] = request.refresh_token

        data["app_context"] = (
            None  # oauth2 flow doesn't have app_context at refresh time, but keep the field for consistency
        )

        return OAuth2Token.model_validate(data)
