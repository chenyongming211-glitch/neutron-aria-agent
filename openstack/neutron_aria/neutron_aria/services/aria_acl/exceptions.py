from __future__ import absolute_import

from neutron_aria.db.aria_acl.errors import AriaAclConflictError
from neutron_aria.db.aria_acl.errors import AriaAclNotFound
from neutron_aria.db.aria_acl.errors import AriaAclValidationError


try:
    from neutron.common import exceptions as neutron_exc
except Exception:
    neutron_exc = None


if neutron_exc is not None:
    class AriaAclBadRequest(neutron_exc.BadRequest):
        message = "Invalid Aria ACL request: %(reason)s"

        def __init__(self, reason):
            super(AriaAclBadRequest, self).__init__(reason=reason)


    class AriaAclResourceNotFound(neutron_exc.NotFound):
        message = "Aria ACL resource not found: %(reason)s"

        def __init__(self, reason):
            super(AriaAclResourceNotFound, self).__init__(reason=reason)


    class AriaAclConflict(neutron_exc.Conflict):
        message = "Aria ACL write conflict: %(reason)s"

        def __init__(self, reason):
            super(AriaAclConflict, self).__init__(reason=reason)
else:
    class _FallbackHttpError(Exception):
        status_code = 500

        def __init__(self, reason):
            self.reason = str(reason)
            super(_FallbackHttpError, self).__init__(self.reason)


    class AriaAclBadRequest(_FallbackHttpError):
        status_code = 400


    class AriaAclResourceNotFound(_FallbackHttpError):
        status_code = 404


    class AriaAclConflict(_FallbackHttpError):
        status_code = 409


def map_repository_error(exc):
    if isinstance(exc, AriaAclConflictError):
        return AriaAclConflict(str(exc))
    if isinstance(exc, AriaAclValidationError):
        return AriaAclBadRequest(str(exc))
    if isinstance(exc, AriaAclNotFound):
        return AriaAclResourceNotFound(str(exc))
    return exc


class ErrorMappingRepositoryProxy(object):
    def __init__(self, repository):
        self.repository = repository

    def __getattr__(self, name):
        attribute = getattr(self.repository, name)
        if not callable(attribute):
            return attribute

        def mapped_call(*args, **kwargs):
            try:
                return attribute(*args, **kwargs)
            except (
                AriaAclConflictError,
                AriaAclValidationError,
                AriaAclNotFound,
            ) as exc:
                raise map_repository_error(exc)

        return mapped_call
