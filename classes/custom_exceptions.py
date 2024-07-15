"""
A module for custom exceptions:
     - FileDoesNotExistError
     - NotAnIntegerError
     - InvalidNameserversError
"""


class FileDoesNotExistError(Exception):
    """
    Custom exception that indicates a non-existent file.
    Raised when attempting to access a file that does not exist in the file system.
    """

    pass


class NotAnIntegerError(Exception):
    """
    Represents an exception raised when expected value is not an integer.
    Inherits from the base Exception class. Usage:

    To raise a NotAnIntegerError exception, use the `raise` statement:
    Example:
        try:
            raise NotAnIntegerError("The value should be an integer.")
        except NotAnIntegerError as e:
            print(e)
    Output: The value should be an integer.
    """

    pass


class InvalidNameserversError(Exception):
    """
    Exception for invalid nameservers. Raised when an invalid nameserver is encountered.
    """

    pass
