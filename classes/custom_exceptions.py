class FileDoesNotExistError(Exception):
    pass


class NotAnIntegerError(Exception):
    pass


class InvalidNameserversError(Exception):
    pass


class ProviderCatalogueError(RuntimeError):
    """One or more required cloud provider catalogues are unusable."""


class OutputWriteError(RuntimeError):
    """A required run output could not be created or written."""
