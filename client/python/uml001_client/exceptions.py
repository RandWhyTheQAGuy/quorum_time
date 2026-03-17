class ApiError(Exception):
    """Base class for all client-side API errors."""
    pass

class AuthError(ApiError):
    """Raised when the server returns 401 Unauthorized."""
    pass

class ServerError(ApiError):
    """Raised when the server returns 5xx or unexpected responses."""
    pass
