"""
UML-001 Python Client Module
============================
Exposes the high-level API client and data models for REST communication
with the Aegis Clock server.
"""

from .api import Uml001Client
from .models import (
    TimeObservation,
    BftSyncResult,
    SharedStateMessage,
)
from .exceptions import (
    ApiError,
    AuthError,
    ServerError,
)

# Defining __all__ ensures that 'from uml001_client import *' 
# only pulls in the intended public API.
__all__ = [
    "Uml001Client",
    "TimeObservation",
    "BftSyncResult",
    "SharedStateMessage",
    "ApiError",
    "AuthError",
    "ServerError",
]