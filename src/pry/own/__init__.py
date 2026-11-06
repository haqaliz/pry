"""Ownership verification primitives for Pry."""

from pry.own.errors import OwnershipError
from pry.own.target import Target, normalize_target

__all__ = ["OwnershipError", "Target", "normalize_target"]
