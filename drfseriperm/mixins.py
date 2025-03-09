from __future__ import annotations

__all__ = (
    'FieldsForPermissions',
    'PermissionBasedModelSerializerMixin',
)

import collections
import contextlib
import copy
import http
import typing

import rest_framework.permissions
import rest_framework.request
import rest_framework.serializers
import rest_framework.utils.model_meta
import rest_framework.views

P = typing.ParamSpec('P')


class FieldsForPermissions:
    """
    data container to be passed into PermissionBasedSerializerMixin
    """

    def __init__(
        self,
        include: typing.Iterable[str] = None,
        exclude: typing.Iterable[str] = None,
        permissions: typing.Iterable[
            rest_framework.permissions.BasePermission | str
        ] = None,
        extra_kwargs: dict[str, dict[str, typing.Any]] = None,
        http_methods: typing.Iterable[str] = ...,
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

        self.include = self._format_fields(include)
        self.exclude = self._format_fields(exclude)
        self.permissions = self._format_permissions(permissions)
        self.extra_kwargs = self._format_extra_kwargs(extra_kwargs)
        self.http_methods = self._format_http_methods(http_methods)

    @staticmethod
    def _format_fields(fields: typing.Iterable[str] | None) -> list[str]:
        if fields is None:
            return []

        if (
            fields == rest_framework.serializers.ALL_FIELDS
            or rest_framework.serializers.ALL_FIELDS in fields
        ):
            return rest_framework.serializers.ALL_FIELDS

        return list(collections.OrderedDict.fromkeys(fields))

    @staticmethod
    def _format_permissions(
        permissions: typing.Iterable[
            rest_framework.permissions.BasePermission | str
        ] | None,
    ) -> set[rest_framework.permissions.BasePermission | str, ...]:
        return set(permissions) if permissions is not None else set()

    @staticmethod
    def _format_extra_kwargs(
        extra_kwargs: dict[str, dict[str, typing.Any]] | None,
    ) -> dict[str, dict[str, typing.Any]]:
        return copy.deepcopy(extra_kwargs) if extra_kwargs is not None else {}

    @staticmethod
    def _format_http_methods(
        http_methods: typing.Iterable[str] | Ellipsis,
    ) -> list[str, ...]:
        if http_methods != Ellipsis:
            return list(map(str.upper, http_methods))

        return [
            http.HTTPMethod.GET,
            http.HTTPMethod.POST,
            http.HTTPMethod.PUT,
            http.HTTPMethod.PATCH,
            http.HTTPMethod.DELETE,
            http.HTTPMethod.HEAD,
            http.HTTPMethod.OPTIONS,
            http.HTTPMethod.TRACE,
        ]

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


class _SerializerContextMixin:

    def _get_request(self) -> rest_framework.request.Request:
        return self.context['request']

    def _get_view(self) -> rest_framework.views.APIView:
        return self.context['view']


class _SerializerFFPsMetaMixin:

    def _get_meta_fields(self) -> list[str, ...] | None:
        return getattr(self.Meta, 'fields', None)

    def _get_meta_exclude(self) -> list[str, ...] | None:
        return getattr(self.Meta, 'exclude', None)

    def get_list_ffps(
        self,
    ) -> list[FieldsForPermissions, ...]:
        """
        returns the list of :class:`FieldsForPermissions`.
        If "list_fields_for_permissions" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, empty list will be returned
        """

        return getattr(self.Meta, 'list_fields_for_permissions', [])

    def get_ffps_reverse_state(self) -> bool:
        """
        returns the boolean value which indicates if
        we should reverse list of fields for permissions.
        If "reverse_list_fields_for_permissions" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, False will be returned
        """

        return getattr(self.Meta, 'reverse_list_fields_for_permissions', False)

    def get_ffps_inherit_state(self) -> bool:
        """
        returns the boolean value which indicates if
        we should inherit the include/exclude parameters of the previous
        allowed for the user, which is accessing the endpoint,
        :class:`FieldsForPermissions`.
        If "inherit_list_fields_for_permissions" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, True will be returned
        """

        return getattr(self.Meta, 'inherit_list_fields_for_permissions', True)

    def get_extra_kwargs_inherit_state(self) -> bool:
        """
        returns the boolean value which indicates if
        we should inherit the extra_kwargs parameter of the previous
        allowed for the user, which is accessing the endpoint,
        :class:`FieldsForPermissions`.
        If "inherit_fields_for_permissions_extra_kwargs" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, True will be returned
        """

        return getattr(
            self.Meta,
            'inherit_fields_for_permissions_extra_kwargs',
            True,
        )


class PermissionBasedModelSerializerMixin(_SerializerContextMixin,
                                          _SerializerFFPsMetaMixin):

    def get_default_serializer_fields(
        self,
        *args: typing.Any,
    ) -> list[str, ...]:
        """
        builds the list of field names
        from model's fields and the field names
        specified in Meta.fields and Meta.exclude,
        if no one of Meta attributes mentioned above is specified,
        then an empty list is returned
        """

        if not self._get_meta_fields() and not self._get_meta_exclude():
            return []
        # don't override get_default_field_names(),
        # since the super method is not expecting to obtain an empty list
        return super().get_field_names(*args)

    @contextlib.contextmanager
    def _all_fields_meta(self) -> list[str, ...]:
        """
        contextmanager which mocks the
        Meta.fields attribute to have ALL_FIELDS value
        and Meta.exclude to have a value of an empty list
        """

        meta_fields = self._get_meta_fields()
        meta_exclude = self._get_meta_exclude()

        try:
            self.Meta.fields = rest_framework.serializers.ALL_FIELDS
            self.Meta.exclude = None
            yield
        finally:
            self.Meta.fields = meta_fields
            self.Meta.exclude = meta_exclude

    def _get_user_permissions(
            self,
    ) -> list[rest_framework.permissions.BasePermission, ...]:
        """
        returns the list of all the permissions
        (:class:`BasePermissions`) which user has
        """

        return self._get_request().user.get_all_permissions()

    def _check_permissions(
        self,
        required: list[str | rest_framework.permissions.BasePermission, ...],
        has: list[str, ...],
    ) -> bool:
        """
        compares the user permissions and the required permissions
        and returns the boolean value indicating if user has enough
        permission to have the current ffp, for which checking, applied
        """

        request = self._get_request()
        view = self._get_view()

        for permission in required:
            if isinstance(permission, str) and permission not in has:
                return False

            with contextlib.suppress(TypeError):
                if not permission().has_permission(request, view, self):
                    return False

            if not permission().has_permission(request, view):
                return False

        return True

    def get_user_permitted_ffps(self) -> list[FieldsForPermissions, ...]:
        """
        returns the list of :class:`FieldsForPermissions` which should
        be applied to the serializer depending on user's permissions
        """

        user_permissions = self._get_user_permissions()
        permissions_ffps = self.get_list_ffps()
        if self.get_ffps_reverse_state():
            permissions_ffps.reverse()

        permitted_ffps = []

        for ffp in permissions_ffps:
            if not self._check_permissions(
                ffp.permissions,
                user_permissions,
            ):
                continue

            permitted_ffps.append(ffp)

        return permitted_ffps

    def _filter_field_names(
        self,
        ffp: FieldsForPermissions,
        field_names: list[str, ...],
        *args: typing.Any,
    ) -> list[str, ...]:
        """
        joins ffp's include and exclude fields
        with field_names (list of field names inherited
        from the ffp placed above, or lower
        if reversing order with
        reverse_list_fields_for_permissions = True)
        """

        fields = field_names.copy()
        with self._all_fields_meta():
            all_fields = self.get_default_serializer_fields(*args)

        # getting include/exclude fields
        # and replacing ALL_FIELDS with real fields
        ffp_include, ffp_exclude = (
            f if f != rest_framework.serializers.ALL_FIELDS else all_fields
            for f in (ffp.include, ffp.exclude)
        )

        for field in ffp_include:
            assert field in all_fields, (
                f'Cannot include field "{field}" since it does not belong '
                f'neither to the serializer nor to the model'
            )

            assert field not in ffp_exclude, (
                f'Cannot both include and exclude field "{field}"'
            )

            if field not in fields:
                fields.append(field)

        for exclude_field in ffp_exclude:
            if exclude_field in fields:
                fields.remove(exclude_field)

        return fields

    def _reduce_ffps(
        self,
        *ffps: FieldsForPermissions,
        callback: typing.Callable[
            [P.args, P.kwargs],
            typing.Iterable[typing.Any],
        ],
        callback_args: typing.Iterable = None,
        callback_kwargs: dict[str, typing.Any] = None,
        inherit: bool = True,
        default: typing.Iterable = None,
    ) -> typing.Collection | None:
        """
        joins all the ffps given with checking
        inherit state, checking request method and
        calling the filtering method. Should be called
        for reducing field names and extra kwargs stacks
        """

        if not callback_args:
            callback_args = ()
        if not callback_kwargs:
            callback_kwargs = {}

        if not inherit:
            ffps = (ffps[-1],) if ffps else ()

        joined = copy.deepcopy(default)

        for ffp in ffps:
            request_method = self._get_request().method.upper()
            ffp_methods = map(str.upper, ffp.http_methods)

            if request_method not in ffp_methods:
                continue

            joined = callback(ffp, joined, *callback_args, **callback_kwargs)

        return joined

    def _reduce_field_names_callback(
        self,
        ffp: FieldsForPermissions,
        field_names: list[str, ...],
        *args: typing.Any,
    ) -> list[str, ...]:
        """
        callback to be passed into the _reduce_ffps()
        method to join all the field names into a single list
        """

        for field in self._filter_field_names(ffp, field_names, *args):
            if field not in field_names:
                field_names.append(field)

        return field_names

    def get_field_names(self, *args: typing.Any) -> list[str, ...]:
        """
        gets field names to be serialized for the current request

        Parameters
        ----------
        args:
          declared_fields and info, you can read more about them
          from the Django REST framework documentation
        """

        return self._reduce_ffps(
            *self.get_user_permitted_ffps(),
            callback=self._reduce_field_names_callback,
            callback_args=args,
            inherit=self.get_ffps_inherit_state(),
            default=self.get_default_serializer_fields(),
        )

    @staticmethod
    def _reduce_extra_kwargs_callback(
        ffp: FieldsForPermissions,
        extra_kwargs: dict[str, dict[str, typing.Any]],
    ) -> dict[str, dict[str, typing.Any]]:
        """
        callback to be passed into the _reduce_ffps()
        method to join all the extra kwargs into a single dictionary
        """

        for field, kwargs in ffp.extra_kwargs.items():
            field_kwargs = copy.deepcopy(kwargs)

            if field not in extra_kwargs:
                extra_kwargs[field] = {}

            for k, v in field_kwargs.items():
                extra_kwargs[field][k] = v

        return extra_kwargs

    def get_default_serializer_extra_kwargs(self) -> None:
        """
        gets extra kwargs specified in Meta.extra_kwargs
        """

        return super().get_extra_kwargs()

    def get_extra_kwargs(self) -> dict[str, dict[str, typing.Any]]:
        """
        gets serializer fields' extra kwargs for the current request
        """

        return self._reduce_ffps(
            *self.get_user_permitted_ffps(),
            callback=self._reduce_extra_kwargs_callback,
            inherit=self.get_extra_kwargs_inherit_state(),
            default=self.get_default_serializer_extra_kwargs(),
        )
