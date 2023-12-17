"""PyAsusWRT Exceptions implementation"""

import asyncio
from typing import Any, Optional

import aiohttp


class AsusWrtError(Exception):
    """Base class for all errors raised by this library."""

    def __init__(
        self, *args: Any, message: Optional[str] = None, **_kwargs: Any
    ) -> None:
        """Initialize base AsusWrtError."""
        super().__init__(*args, message)


class AsusWrtCommunicationError(AsusWrtError, aiohttp.ClientError):
    """Error occurred while communicating with the AsusWrt device ."""


class AsusWrtResponseError(AsusWrtCommunicationError):
    """HTTP error code returned by the AsusWrt device."""

    def __init__(
        self,
        *args: Any,
        status: int,
        headers: Optional[aiohttp.typedefs.LooseHeaders] = None,
        message: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize."""
        if not message:
            message = f"Did not receive HTTP 200 but {status}"
        super().__init__(*args, message=message, **kwargs)
        self.status = status
        self.headers = headers


class AsusWrtClientResponseError(aiohttp.ClientResponseError, AsusWrtResponseError):
    """HTTP response error with more details from aiohttp."""


class AsusWrtConnectionError(AsusWrtCommunicationError, aiohttp.ClientConnectionError):
    """Error connecting with the router."""


class AsusWrtConnectionTimeoutError(
    AsusWrtCommunicationError, aiohttp.ServerTimeoutError, asyncio.TimeoutError
):
    """Timeout while communicating with the device."""


class AsusWrtLoginError(AsusWrtError):
    """Login error / invalid credential."""


class AsusWrtValueError(AsusWrtError, ValueError):
    """Error invalid value received."""


class AsusWrtNotAvailableInfoError(AsusWrtError):
    """Error information not available."""
