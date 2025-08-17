from pydantic import AnyHttpUrl, BaseModel


class OIDCConfig(BaseModel):
    client_id: str
    client_secret: str | None = None  # for standard flow
    redirect_uri: AnyHttpUrl
    authorize_url: AnyHttpUrl
    token_url: AnyHttpUrl
