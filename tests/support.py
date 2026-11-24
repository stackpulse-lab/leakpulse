"""Shared, deterministic fake-credential helpers for the test suite.

Tokens are generated at runtime so that this repository never contains a
literal that looks like a real credential.
"""
from __future__ import annotations

import os
from contextlib import contextmanager


def fake_secret(length: int = 36, prefix: str = "") -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789"
    body = "".join(alphabet[(index * 17 + 11) % len(alphabet)] for index in range(length))
    return prefix + body


def fake_upper(length: int = 16) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(alphabet[(index * 17 + 11) % len(alphabet)] for index in range(length))


@contextmanager
def chdir(path):
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)
