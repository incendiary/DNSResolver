class FileDoesNotExistError(Exception):
    pass


class NotAnIntegerError(Exception):
    pass


class InvalidNameserversError(Exception):
    pass


class ProviderCatalogueError(RuntimeError):
    """One or more required cloud provider catalogues are unusable."""
