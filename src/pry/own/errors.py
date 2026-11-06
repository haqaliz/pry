"""Named failure causes for ownership verification."""

UNSUPPORTED_TARGET = "UNSUPPORTED_TARGET"
BAD_CHALLENGE = "BAD_CHALLENGE"
NO_METHOD = "NO_METHOD"
UNSUPPORTED_METHOD = "UNSUPPORTED_METHOD"
DNS_RECORD_NOT_FOUND = "DNS_RECORD_NOT_FOUND"
DNS_MISMATCH = "DNS_MISMATCH"
DNS_ERROR = "DNS_ERROR"
WELL_KNOWN_NOT_FOUND = "WELL_KNOWN_NOT_FOUND"
WELL_KNOWN_MISMATCH = "WELL_KNOWN_MISMATCH"
WELL_KNOWN_REDIRECT = "WELL_KNOWN_REDIRECT"
WELL_KNOWN_ERROR = "WELL_KNOWN_ERROR"
INSECURE_TRANSPORT = "INSECURE_TRANSPORT"
TOKEN_MALFORMED = "TOKEN_MALFORMED"
TOKEN_BAD_SIGNATURE = "TOKEN_BAD_SIGNATURE"
TOKEN_EXPIRED = "TOKEN_EXPIRED"
TOKEN_TARGET_MISMATCH = "TOKEN_TARGET_MISMATCH"
KEY_INVALID = "KEY_INVALID"


class OwnershipError(Exception):
    """A verification failure with a stable, machine-readable cause."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause
        self.message = message

    def __str__(self) -> str:
        return "%s: %s" % (self.cause, self.message)
