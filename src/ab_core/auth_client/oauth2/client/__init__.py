from typing import Annotated, Union

from pydantic import Discriminator

from .pkce import PKCEOAuth2Client
from .standard import StandardOAuth2Client

OAuth2Client = Annotated[
    StandardOAuth2Client | PKCEOAuth2Client,
    Discriminator("type"),
]
