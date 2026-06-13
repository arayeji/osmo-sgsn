#!/usr/bin/env python3
import uvicorn

from osmo_sgsn_api.config import settings


def main() -> None:
    uvicorn.run(
        "osmo_sgsn_api.main:app",
        host=settings.osmo_sgsn_api_host,
        port=settings.osmo_sgsn_api_port,
        reload=False,
    )


if __name__ == "__main__":
    main()
