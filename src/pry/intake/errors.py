"""Named failure causes for local intake."""

REPO_NOT_FOUND = "REPO_NOT_FOUND"
UNSUPPORTED_PROJECT = "UNSUPPORTED_PROJECT"
DOCKER_UNAVAILABLE = "DOCKER_UNAVAILABLE"
COPY_FAILED = "COPY_FAILED"
BUILD_FAILED = "BUILD_FAILED"
START_FAILED = "START_FAILED"
READY_TIMEOUT = "READY_TIMEOUT"
SANDBOX_ERROR = "SANDBOX_ERROR"
SNAPSHOT_FAILED = "SNAPSHOT_FAILED"
INTERRUPTED = "INTERRUPTED"


class IntakeError(Exception):
    """An intake failure with a stable, machine-readable cause."""

    def __init__(self, cause: str, message: str) -> None:
        super().__init__(message)
        self.cause = cause
        self.message = message

    def __str__(self) -> str:
        return "%s: %s" % (self.cause, self.message)
