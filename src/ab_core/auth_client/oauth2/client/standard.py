import base64
import secrets
from typing import Literal, override

import requests
from yarl import URL

from ab_core.auth_client.oauth2.schema.authorize import (
    OAuth2AuthorizeResponse,
    OAuth2BuildAuthorizeRequest,
)
from ab_core.auth_client.oauth2.schema.client_type import OAuth2ClientType
from ab_core.auth_client.oauth2.schema.exchange import (
    OAuth2ExchangeCodeRequest,
    OAuth2ExchangeFromRedirectUrlRequest,
)
from ab_core.auth_client.oauth2.schema.refresh import RefreshTokenRequest
from ab_core.auth_client.oauth2.schema.token import OAuth2Token
from ab_core.cache.caches.base import CacheSession

from .base import OAuth2ClientBase


class StandardOAuth2Client(
    OAuth2ClientBase[
        OAuth2BuildAuthorizeRequest,
        OAuth2AuthorizeResponse,
        OAuth2ExchangeCodeRequest,
        OAuth2ExchangeFromRedirectUrlRequest,
    ]
):
    type: Literal[OAuth2ClientType.STANDARD] = OAuth2ClientType.STANDARD

    # ---------- Authorize URL ----------
    @override
    def build_authorize_request(
        self,
        request: OAuth2BuildAuthorizeRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2AuthorizeResponse:
        state = request.state or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")

        q: dict[str, str] = {
            "response_type": request.response_type,
            "client_id": self.config.client_id,
            "redirect_uri": str(self.config.redirect_uri),
            "scope": request.scope,
            "state": state,
        }
        if request.extra_params:
            q.update({k: str(v) for k, v in request.extra_params.items()})

        url = str(URL(str(self.config.authorize_url)).with_query(q))
        # Base returns the base response; subclasses can upcast to their own response type
        return OAuth2AuthorizeResponse(url=url, state=state)

    @override
    def exchange_code(
        self,
        request: OAuth2ExchangeCodeRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token:
        if not self.config.client_secret:
            raise ValueError("client_secret required for standard flow")
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": str(self.config.redirect_uri),
            "code": request.code,
        }
        resp = requests.post(
            self.config.token_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        return OAuth2Token.model_validate(resp.json())

    @override
    def exchange_from_redirect_url(
        self,
        request: OAuth2ExchangeFromRedirectUrlRequest,
        *,
        cache_session: CacheSession | None = None,
    ) -> OAuth2Token:
        if request.enforce_redirect_uri_match:
            self._validate_redirect_uri_match(str(request.redirect_url))
        code, state = self._parse_code_and_state_from_redirect(str(request.redirect_url))
        if request.expected_state is not None and state != request.expected_state:
            raise ValueError("state mismatch")
        return self.exchange_code(OAuth2ExchangeCodeRequest(code=code))

    @override
    def refresh_token(
        self,
        request: RefreshTokenRequest,
        *,
        cache_session: CacheSession | None = None,  # kept for symmetry
    ) -> OAuth2Token:
        if not self.config.client_secret:
            raise ValueError("client_secret required for standard client refresh")

        payload: dict[str, str] = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "refresh_token": request.refresh_token,
        }
        if request.scope:
            payload["scope"] = request.scope  # optional; most IdPs ignore unless narrowing

        resp = requests.post(
            self.config.token_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()

        # Keep original refresh token if server doesn’t rotate it.
        data.setdefault("refresh_token", request.refresh_token)

        return OAuth2Token.model_validate(data)
