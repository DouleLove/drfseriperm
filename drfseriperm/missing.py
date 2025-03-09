from __future__ import annotations

__all__ = ('MISSING',)

import typing


class _Singleton(type):
    _instances = {}

    def __call__(cls, *args: typing.Any, **kwargs: typing.Any) -> _Singleton:
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


class _MissingSentinel(metaclass=_Singleton):
    __slots__ = ()

    def __bool__(self) -> bool:
        return False

    def __eq__(self) -> bool:
        return False

    def __ne__(self) -> bool:
        return True

    def __repr__(self) -> str:
        return '...'


MISSING = _MissingSentinel()
