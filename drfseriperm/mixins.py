from __future__ import annotations

__all__ = ('PermissionBasedModelSerializerMixin',)

import contextlib
import copy
import typing

import rest_framework.exceptions
import rest_framework.permissions
import rest_framework.request
import rest_framework.serializers
import rest_framework.views

from .ffp import FieldsForPermissions
from .missing import MISSING

P = typing.ParamSpec('P')


class _SerializerContextMixin:

    def _get_request(self) -> rest_framework.request.Request:
        return self.context['request']

    def _get_view(self) -> rest_framework.views.APIView:
        return self.context['view']


class _SerializerFFPsContextMetaMixin(_SerializerContextMixin):

    def _get_meta_attr(
        self,
        attr_name: str,
        default: typing.Any = MISSING,
    ) -> typing.Any:
        if default is MISSING:
            return getattr(self.Meta, attr_name)
        return getattr(self.Meta, attr_name, default)

    def get_meta_fields(self) -> list[str, ...] | None:
        """
        returns a list of field names to be included in all ffps.
        If "fields" attribute of "Meta" class
        inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, None will be returned
        """

        return self._get_meta_attr('fields', None)

    def get_meta_exclude(self) -> list[str, ...] | None:
        """
        returns a list of field names to be excluded from all ffps.
        If "exclude" attribute of "Meta" class
        inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, None will be returned
        """

        return self._get_meta_attr('exclude', None)

    def get_meta_extra_kwargs(self) -> None:
        """
        returns a dictionary (field_name: field_properties_dict) pairs
        with an extra kwargs for serializable fields.
        If "extra_kwargs" attribute of "Meta" class
        inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, empty dictionary will be returned
        """

        return super().get_extra_kwargs()

    def get_list_ffps(self) -> list[FieldsForPermissions, ...]:
        """
        returns a list of :class:`FieldsForPermissions`.
        If "list_fields_for_permissions" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, empty list will be returned
        """

        list_ffps = self._get_meta_attr('list_fields_for_permissions', [])

        for idx, ffp in enumerate(list_ffps):
            if not isinstance(ffp, FieldsForPermissions):
                list_ffps[idx] = ffp()
                assert isinstance(list_ffps[idx], FieldsForPermissions), (
                    'given object is not an instance or a class of'
                    ':class:`FieldsForPermissions`'
                )

        return list_ffps

    def get_ffps_reverse_state(self) -> bool:
        """
        returns a boolean value which indicates if
        we should reverse list of fields for permissions.
        If "reverse_list_fields_for_permissions" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, False will be returned
        """

        return self._get_meta_attr(
            'reverse_list_fields_for_permissions',
            False,
        )

    def get_ffps_inherit_state(self) -> bool:
        """
        returns a boolean value which indicates if
        we should inherit the include/exclude parameters of the previous
        allowed for the user, which is accessing the endpoint,
        :class:`FieldsForPermissions`.
        If "inherit_list_fields_for_permissions" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, True will be returned
        """

        return self._get_meta_attr('inherit_list_fields_for_permissions', True)

    def get_extra_kwargs_inherit_state(self) -> bool:
        """
        returns a boolean value which indicates if
        we should inherit the extra_kwargs parameter of the previous
        allowed for the user, which is accessing the endpoint,
        :class:`FieldsForPermissions`.
        If "inherit_fields_for_permissions_extra_kwargs" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, True will be returned
        """

        return self._get_meta_attr(
            'inherit_fields_for_permissions_extra_kwargs',
            True,
        )

    def get_raise_for_no_fields_state(self) -> bool:
        """
        returns a boolean value indicating if
        we should raise exception when there are no fields
        to be serialized.
        If "raise_for_no_fields" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, True will be returned
        """

        return self._get_meta_attr('raise_for_no_fields', True)

    def get_no_fields_exception(
        self,
    ) -> typing.Type[rest_framework.exceptions.APIException]:
        """
        returns an exception instance (or exception class itself)
        which will be raised if there is no fields to show
        for a user for the request method.
        If "no_fields_exception" attribute of
        "Meta" class inside the serializer is specified,
        then the value will be obtained from it.
        Otherwise, :class:`rest_framework.exceptions.MethodNotAllowed`
        instance will be returned
        """

        return self._get_meta_attr(
            'no_fields_exception',
            rest_framework.exceptions.MethodNotAllowed(
                self._get_request().method,
            ),
        )


class PermissionBasedModelSerializerMixin(_SerializerFFPsContextMetaMixin):

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

    def _get_all_field_names(self, *args: typing.Any) -> list[str, ...]:
        with self._all_fields_meta():
            return super().get_field_names(*args)

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
            all_fields = self._get_all_field_names(*args)

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
        inherit state and request method and
        calling the filtering method. Should be called
        for reducing field names and extra kwargs stacks
        """

        if not callback_args:
            callback_args = ()
        if not callback_kwargs:
            callback_kwargs = {}

        if not inherit:
            ffps = (ffps[-1],) if ffps else ()

        joined = copy.deepcopy(default if default is not None else [])

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
            FieldsForPermissions(
                include=self._get_meta_fields() or [],
                exclude=self._get_meta_exclude() or [],
            ),
            callback=self._reduce_field_names_callback,
            callback_args=args,
            inherit=self.get_ffps_inherit_state(),
            default=[],
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

    def get_extra_kwargs(self) -> dict[str, dict[str, typing.Any]]:
        """
        gets serializer fields' extra kwargs for the current request
        """

        return self._reduce_ffps(
            *self.get_user_permitted_ffps(),
            FieldsForPermissions(
                extra_kwargs=self.get_meta_extra_kwargs(),
            ),
            callback=self._reduce_extra_kwargs_callback,
            inherit=self.get_extra_kwargs_inherit_state(),
            default={},
        )

    def _is_empty_fields_list(self, *fields: rest_framework) -> bool:
        """
        checks if there is at least one field to display
        for a user according to request method
        """

        request_http_method = self._get_request().method
        # If request method is safe (GET, HEAD, OPTIONS)
        # then fields should not have 'write_only' extra kwarg
        # to be displayed. Otherwise, fields should not have 'read_only'
        # extra kwarg to be displayed
        if request_http_method in rest_framework.permissions.SAFE_METHODS:
            negative_lookup_field_attr = 'write_only'
        else:
            negative_lookup_field_attr = 'read_only'

        for field in fields:
            if not getattr(field, negative_lookup_field_attr):
                return False

        return True

    def get_fields(self) -> dict[
        str,
        rest_framework.fields.Field | list[rest_framework.fields.Field, ...]
    ]:
        fields = super().get_fields()

        # raise for empty fields list if raise state is True
        if (
            self._is_empty_fields_list(*fields.values())
            and self.get_raise_for_no_fields_state()
        ):
            raise self.get_no_fields_exception()

        return fields
