__all__ = (
    'FieldsForPermissions',
    'PermissionBasedSerializerFieldsMixin',
)

import collections
import contextlib
import copy
import typing

import rest_framework.permissions
import rest_framework.request
import rest_framework.serializers
import rest_framework.views

P = typing.ParamSpec('P')


class FieldsForPermissions:

    def __init__(
        self,
        *fields: typing.Iterable[str],
        permissions: typing.Any = None,
        exclude: bool = False,
        extra_kwargs: dict[str, dict[str, typing.Any]] = None,
    ) -> None:
        self.permissions = set(permissions) if permissions else set()
        self.fields = tuple(collections.OrderedDict.fromkeys(fields))
        self.exclude = exclude
        self.extra_kwargs = copy.deepcopy(extra_kwargs) if extra_kwargs else {}


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
        return getattr(self.Meta, 'list_fields_for_permissions', [])

    def get_ffps_reverse_state(self) -> bool:
        return getattr(self.Meta, 'reverse_list_fields_for_permissions', False)

    def get_ffps_inherit_state(self) -> bool:
        return getattr(self.Meta, 'inherit_list_fields_for_permissions', True)

    def get_extra_kwargs_inherit_state(self) -> bool:
        return getattr(
            self.Meta,
            'inherit_fields_for_permissions_extra_kwargs',
            True,
        )


class PermissionBasedSerializerFieldsMixin(_SerializerContextMixin,
                                           _SerializerFFPsMetaMixin):

    @contextlib.contextmanager
    def _all_fields_meta(self) -> list[str, ...]:
        meta_fields = self._get_meta_fields()
        meta_exclude = self._get_meta_exclude()

        try:
            self.Meta.fields = rest_framework.serializers.ALL_FIELDS
            self.Meta.exclude = None
            yield
        finally:
            self.Meta.fields = meta_fields
            self.Meta.exclude = meta_exclude

    def get_default_serializer_fields(
        self,
        *args: typing.Any,
    ) -> list[str, ...]:
        if not self._get_meta_fields() and not self._get_meta_exclude():
            return []
        return super().get_field_names(*args).copy()

    def get_default_serializer_extra_kwargs(self) -> None:
        return super().get_extra_kwargs()

    def _get_user_permissions(self) -> list:
        return self._get_request().user.get_all_permissions()

    def _check_permissions(
        self,
        required: list[str | rest_framework.permissions.BasePermission, ...],
        has: list[str, ...],
    ) -> bool:
        request = self._get_request()
        view = self._get_view()

        for permission in required:
            try:
                if not permission().has_permission(request, view):
                    return False
            except TypeError:
                if permission not in has:
                    return False

        return True

    def get_user_permitted_ffps(self) -> list[FieldsForPermissions, ...]:
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
        *args: typing.Any,
    ) -> list[str, ...]:
        default_fields = self.get_default_serializer_fields(*args)
        fields = default_fields.copy()
        with self._all_fields_meta():
            all_fields = self.get_default_serializer_fields(*args)

        if rest_framework.serializers.ALL_FIELDS in ffp.fields:
            return [] if ffp.exclude else all_fields

        for field in ffp.fields:
            if ffp.exclude:
                assert field in default_fields, (
                    f'Cannot exclude field "{field}" since it is not '
                    f'specified in "Meta.fields" of the appropriate serializer'
                )

                fields.remove(field)
                continue

            assert field not in default_fields, (
                f'Cannot include field "{field}" since it is already '
                f'listed in "Meta.fields" of the corresponding serializer'
            )
            assert field in all_fields, (
                f'Cannot include field "{field}" since it does not belong '
                f'neither to the serializer nor to the model'
            )

            fields.append(field)

        return fields

    @staticmethod
    def _reduce_ffps(
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
        if not callback_args:
            callback_args = ()
        if not callback_kwargs:
            callback_kwargs = {}

        if not inherit:
            ffps = (ffps[-1],) if ffps else ()

        joined = copy.deepcopy(default)

        for ffp in ffps:
            joined = callback(ffp, joined, *callback_args, **callback_kwargs)

        return joined

    def _reduce_field_names_callback(
        self,
        ffp: FieldsForPermissions,
        field_names: list[str, ...],
        *args: typing.Any,
    ) -> list[str, ...]:
        for field in self._filter_field_names(ffp, *args):
            if field not in field_names:
                field_names.append(field)

        return field_names

    def get_field_names(self, *args: typing.Any) -> list[str, ...]:
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
        for field, kwargs in ffp.extra_kwargs.items():
            field_kwargs = copy.deepcopy(kwargs)

            if field not in extra_kwargs:
                extra_kwargs[field] = {}

            for k, v in field_kwargs.items():
                extra_kwargs[field][k] = v

        return extra_kwargs

    def get_extra_kwargs(self) -> dict[str, dict[str, typing.Any]]:
        return self._reduce_ffps(
            *self.get_user_permitted_ffps(),
            callback=self._reduce_extra_kwargs_callback,
            inherit=self.get_extra_kwargs_inherit_state(),
            default=self.get_default_serializer_extra_kwargs(),
        )
