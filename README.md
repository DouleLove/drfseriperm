# drfseriperm
Library for Django REST framework which provides permissions-based serialization

<br>

## Installing

> [!NOTE]
> It's recommended to activate
> <a href="https://docs.python.org/3/library/venv.html">Virtual Environment</a>
> before installing drfseriperm

To clone and install required packages use the following command:
```bash
# linux/macOS
$ python3 -m pip install drfseriperm

# windows
$ py -3 -m pip install drfseriperm
```

<br>

## Quick example
```py
import rest_framework.permissions
import rest_framework.serializers

import drfseriperm


class DefaultUserFFP(drfseriperm.FieldsForPermissions):
    include = ['id', 'username', 'date_joined']
    extra_kwargs = {
        'username': {'read_only': True},
        'date_joined': {'read_only': True},
    }


class StaffFFP(drfseriperm.FieldsForPermissions):
    include = ['email']
    permissions = [rest_framework.permissions.IsAdminUser]
    extra_kwargs = {
        'username': {'read_only': False},
        'email': {'read_only': True},
    }


class UserSerializer(drfseriperm.PermissionBasedModelSerializerMixin,
                     rest_framework.serializers.ModelSerializer):

    class Meta:
        model = django.contrib.auth.models.User
        list_fields_for_permissions = [
            DefaultUserFFP,
            StaffFFP,
        ]
```
In the given example for all the users fields "id", "username", "date_joined" will be available, BUT
staff and superusers will also have access to "email" field.<br>
While using drfseriperm we should inherit our classes from
the FieldsForPermissions (FFP) class, which works with
`include`, `exclude`, `extra_kwargs`, `permissions` and `http_methods` attributes.
Then FFP instances are built by the `PermissionBasedModelSerializerMixin` from
`list_fields_for_permissions` meta attribute and then converted to the list of the available for the user fields

<br>

## FieldsForPermissions
Container and formatter for parameters to be passed into `PermissionBasedModelSerializerMixin`.<br>
Parameters:
- `include` — names of fields to be included for some permission group
- `exclude` — names of fields to be excluded for some permission group
- `permissions` — permissions (DRF `BasePermission` instance) which are required to consider the FFP
- `extra_kwargs` — extra kwargs for fields (e.g. "read_only", "required", "default"),
  has the same structure as the DRF extra_kwargs meta attribute 
  (more information can be seen on Django REST framework official documentation).
  Note that these kwargs are applied to fields when the complete list of fields is built,
  so even if field is not specified in include or exclude it will anyway receive the extra kwargs
- `http_methods` — names of http methods for which FFP is applied
All of them can be either specified as a class attributes or passed as init params 

<br>

## PermissionBasedModelSerializerMixin
Mixin for DRF `ModelSerializer` which filters fields available for the user based on their permissions and request method.
This mixin works with attributes specified in `Meta` class of a `ModelSerializer` subclass.
Meta attributes:
- `list_fields_for_permissions` - list containing subclasses or instances of `FieldsForPermissions`.
  DRF `ALL_FIELDS` (or `__all__`) are also appropriate values
  (to dynamically get this list "get_list_ffps()" method can be overriden, defaults to empty list)
- `inherit_list_fields_for_permissions` - boolean value indicating if an FFP should inherit fields of a
  previous available for request FFP
  (to dynamically get this value "get_ffps_inherit_state()" method can be overriden, defaults to True)
- `reverse_list_fields_for_permissions` - boolean value showing if mixin should apply FFPs specified in
  `list_fields_for_permission` in reversed order or not 
  (to_dynamically get this value, "get_ffps_reverse_state()" method can be overriden, default to False)
- `inherit_fields_for_permissions_extra_kwargs` - boolean value letting mixin know if FFPs should inherit extra kwargs
  of a previous available for request FFP
  (to dynamically get this value "get_extra_kwargs_inherit_state()" method can be overriden, defaults to True)
- `raise_for_no_fields` - boolean value standing for raising an exception in case if no fields are available for
  request method
  (e.g. if all the FFPs have `http_methods` parameter set to ['GET'], then for other http methods the exception will
  be raised, to dynamically get this value "get_raise_for_no_fields_state()" method can be overriden, defaults to True)
- `no_fields_exception` - DRF `APIException` subclass or instance, which is an exception to be raised in case if there
  are no fields available for a request and `raise_for_no_fields` is set to True
  (to dynamically get this value, "get_no_fields_exception()" method can be overriden, default to DRF `MethodNotAllowed`
  with 405 http status)

Also `PermissionBasedModelSerializerMixin` respects native meta attributes of `ModelSerializer` related to fields:
- `fields` - list of field names, which will be included in all the FFPs passed
- `exclude` - list of field names, which will be excluded from all the FFPs passed
- `extra_kwargs` - dictionary containing field_name-field_properties pairs,
  which will be considered by all the FFPs passed
