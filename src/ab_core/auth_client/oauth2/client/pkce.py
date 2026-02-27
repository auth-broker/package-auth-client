import base64
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


class PKCEOAuth2Client(
    OAuth2ClientBase[
        PKCEBuildAuthorizeRequest,
        PKCEAuthorizeResponse,
        PKCEExchangeCodeRequest,
        PKCEExchangeFromRedirectUrlRequest,
    ]
):
    type: Literal[OAuth2ClientType.PKCE] = OAuth2ClientType.PKCE

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
            cache_session.set(
                key=f"pkce:{res.state}",
                value={
                    "verifier": res.code_verifier,
                    "app_context": request.app_context,
                },
                expiry=request.state_ttl,
            )

        return res

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
            await cache_session.set(  # assume async cache has awaitable set
                key=f"pkce:{res.state}",
                value={
                    "verifier": res.code_verifier,
                    "app_context": request.app_context,
                },
                expiry=request.state_ttl,
            )

        return res

    # ---- exchanges ----
    @override
    def exchange_code(
        self,
        request: PKCEExchangeCodeRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token:
        # in pkce code verifier is needed during exchange
        code_verifier = request.code_verifier
        if code_verifier is None:
            if not request.state:
                raise ValueError("code_verifier missing; provide it or supply state for cache lookup")
            code_verifier = self._lookup_verifier(
                state=request.state,
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
        return OAuth2Token.model_validate(resp.json())

    async def exchange_code_async(
        self,
        request: PKCEExchangeCodeRequest,
        *,
        cache_session: CacheAsyncSession | None = None,
    ) -> OAuth2Token:
        code_verifier = request.code_verifier
        if code_verifier is None:
            if not request.state:
                raise ValueError("code_verifier missing; provide it or supply state for cache lookup")
            code_verifier = await self._lookup_verifier_async(
                state=request.state,
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
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                str(self.config.token_url),
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
        resp.raise_for_status()
        return OAuth2Token.model_validate(resp.json())

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
        if not state and request.code_verifier is None:
            raise ValueError("no state in redirect URL and no code_verifier supplied")

        code_verifier = request.code_verifier
        if code_verifier is None:
            code_verifier = self._lookup_verifier(
                state=state,
                delete_after=request.delete_after,
                cache_session=cache_session,
            )

        payload = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": str(self.config.redirect_uri),
            "code": code,
            "code_verifier": code_verifier,
        }
        resp = requests.post(
            self.config.token_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return OAuth2Token.model_validate(resp.json())

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
        if not state and request.code_verifier is None:
            raise ValueError("no state in redirect URL and no code_verifier supplied")

        code_verifier = request.code_verifier
        if code_verifier is None:
            code_verifier = await self._lookup_verifier_async(
                state=state,  # type: ignore[arg-type]
                delete_after=request.delete_after,
                cache_session=cache_session,
            )

        payload = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "redirect_uri": str(self.config.redirect_uri),
            "code": code,
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
        return OAuth2Token.model_validate(resp.json())

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

        return OAuth2Token.model_validate(data)

    # ---- internals ----
    def _lookup_verifier(
        self,
        *,
        state: str,
        delete_after: bool,
        cache_session: CacheSession | None = None,
    ) -> str:
        if cache_session is None:
            raise ValueError("code_verifier not provided and no cache_session configured on client")
        rec = cache_session.get(f"pkce:{state}")
        if rec is None or "verifier" not in rec:
            raise ValueError("code_verifier not found in cache for given state")
        if delete_after:
            cache_session.delete(f"pkce:{state}")
        return rec["verifier"]

    async def _lookup_verifier_async(
        self,
        *,
        state: str,
        delete_after: bool,
        cache_session: CacheAsyncSession | None = None,
    ) -> str:
        if cache_session is None:
            raise ValueError("code_verifier not provided and no cache_session configured on client")
        rec = await cache_session.get(f"pkce:{state}")
        if rec is None or "verifier" not in rec:
            raise ValueError("code_verifier not found in cache for given state")
        if delete_after:
            await cache_session.delete(f"pkce:{state}")
        return rec["verifier"]
