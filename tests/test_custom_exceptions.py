"""
Tests for custom exceptions.

Shows the simplest possible pattern: raise the exception in a pytest.raises
block and assert on the message.  Also demonstrates that each exception is
a subclass of the built-in Exception so callers can catch it generically.
"""

import pytest

from classes.custom_exceptions import (
    FileDoesNotExistError,
    InvalidNameserversError,
    NotAnIntegerError,
)


def test_file_does_not_exist_error_is_raised():
    with pytest.raises(FileDoesNotExistError):
        raise FileDoesNotExistError("no such file")


def test_file_does_not_exist_error_preserves_message():
    with pytest.raises(FileDoesNotExistError, match="no such file"):
        raise FileDoesNotExistError("no such file")


def test_file_does_not_exist_error_is_exception():
    assert issubclass(FileDoesNotExistError, Exception)


def test_not_an_integer_error_is_raised():
    with pytest.raises(NotAnIntegerError):
        raise NotAnIntegerError("expected int, got str")


def test_not_an_integer_error_preserves_message():
    with pytest.raises(NotAnIntegerError, match="expected int"):
        raise NotAnIntegerError("expected int, got str")


def test_not_an_integer_error_is_exception():
    assert issubclass(NotAnIntegerError, Exception)


def test_invalid_nameservers_error_is_raised():
    with pytest.raises(InvalidNameserversError):
        raise InvalidNameserversError("bad nameserver")


def test_invalid_nameservers_error_preserves_message():
    with pytest.raises(InvalidNameserversError, match="bad nameserver"):
        raise InvalidNameserversError("bad nameserver")


def test_invalid_nameservers_error_is_exception():
    assert issubclass(InvalidNameserversError, Exception)
