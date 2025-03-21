__all__ = ('MISSING',)

import typing


class _Singleton(type):
    _instances = {}

    def __call__(cls, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


class _MissingSentinel(metaclass=_Singleton):
    __slots__ = ()

    def __bool__(self) -> bool:
        return False

    def __eq__(self, other: typing.Any) -> bool:
        return False

    def __ne__(self, other: typing.Any) -> bool:
        return True

    def __repr__(self) -> str:
        return '...'


MISSING = _MissingSentinel()
