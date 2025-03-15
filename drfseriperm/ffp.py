from __future__ import annotations

__all__ = ('FieldsForPermissions',)

import collections
import copy
import http
import typing

import rest_framework.permissions
import rest_framework.serializers

from .missing import MISSING


class _FieldsForPermissionsSetup:
    """
    Base class for :class:`FieldsForPermissions`,
    formats
    """

    def __init__(self, **kwargs: typing.Any) -> None:
        for kwarg in kwargs:
            if kwargs[kwarg] is MISSING:
                # if kwarg is MISSING, trying to get value
                # from attributes of self instance
                kwargs[kwarg] = getattr(self, kwarg, MISSING)
            setattr(self, kwarg, kwargs[kwarg])

            # formatting kwargs and setting defaults if
            # value of some of the kwarg is still MISSING
            # by calling methods with names like "_format_{kwarg}"
            formatter_method_name = f'_format_{kwarg}'
            try:
                formatter = getattr(self, formatter_method_name)
            except AttributeError:
                raise AttributeError(
                    f'Cannot format "{kwarg}" kwarg since'
                    f'"{formatter_method_name}()" method is not implemented'
                )
            formatter()

    @staticmethod
    def _format_fields(fields: typing.Iterable[str] | MISSING) -> list[str]:
        if fields is MISSING:
            return []

        if (
            fields == rest_framework.serializers.ALL_FIELDS
            or rest_framework.serializers.ALL_FIELDS in fields
        ):
            return rest_framework.serializers.ALL_FIELDS

        return list(collections.OrderedDict.fromkeys(fields))

    def _format_include(self) -> None:
        self.include = self._format_fields(self.include)

    def _format_exclude(self) -> None:
        self.exclude = self._format_fields(self.exclude)

    def _format_permissions(self) -> None:
        if self.permissions is MISSING:
            self.permissions = set()

        self.permissions = set(self.permissions)

    def _format_extra_kwargs(self) -> None:
        if self.extra_kwargs is MISSING:
            self.extra_kwargs = {}

        self.extra_kwargs = copy.deepcopy(self.extra_kwargs)

    def _format_http_methods(self) -> None:
        if self.http_methods is MISSING:
            self.http_methods = [
                http.HTTPMethod.GET,
                http.HTTPMethod.POST,
                http.HTTPMethod.PUT,
                http.HTTPMethod.PATCH,
                http.HTTPMethod.DELETE,
                http.HTTPMethod.HEAD,
                http.HTTPMethod.OPTIONS,
                http.HTTPMethod.TRACE,
            ]

        self.http_methods = list(map(str.upper, self.http_methods))


class FieldsForPermissions(_FieldsForPermissionsSetup):
    """
    data container to be passed into PermissionBasedSerializerMixin
    """

    def __init__(
        self,
        include: typing.Iterable[str] = MISSING,
        exclude: typing.Iterable[str] = MISSING,
        permissions: typing.Iterable[
            rest_framework.permissions.BasePermission | str
        ] = MISSING,
        extra_kwargs: dict[str, dict[str, typing.Any]] = MISSING,
        http_methods: typing.Iterable[str] = MISSING,
    ) -> None:
        """
        Parameters
        ----------
        include:
          fields to be included in the list of serializable fields
        exclude:
          fields to be excluded from the list of serializable fields
        permissions:
          permission which are needed to include or exclude fields from
          the list of serializable fields
        extra_kwargs:
          field_name-kwargs pairs which are used to modify fields
          (e.g. make them read-only), you can view all the allowed
          values for this parameter in the Django REST framework
          documentation
        http_methods:
          names of http methods for which include/exclude/extra_kwargs
          parameters should be applied
        """

        super().__init__(
            include=include,
            exclude=exclude,
            permissions=permissions,
            extra_kwargs=extra_kwargs,
            http_methods=http_methods,
        )

    def __iter__(self) -> typing.Iterable:
        return iter((
            copy.copy(self.include),
            copy.copy(self.exclude),
            copy.copy(self.permissions),
            copy.deepcopy(self.extra_kwargs),
            copy.copy(self.http_methods),
        ))

    def __copy__(self) -> FieldsForPermissions:
        return FieldsForPermissions(*self)

    copy = __copy__
