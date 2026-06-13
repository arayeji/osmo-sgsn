from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    osmo_sgsn_api_token: str = "change-me"
    osmo_sgsn_vty_host: str = "127.0.0.1"
    osmo_sgsn_vty_port: int = 4245
    osmo_sgsn_api_host: str = "0.0.0.0"
    osmo_sgsn_api_port: int = 8088
    osmo_sgsn_vty_timeout: float = 30.0


settings = Settings()
