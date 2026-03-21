class ApiError(Exception):
    """Base client error."""
    pass

class AuthError(ApiError):
    """401 Unauthorized."""
    pass

class ServerError(ApiError):
    """5xx Server Error."""
    pass