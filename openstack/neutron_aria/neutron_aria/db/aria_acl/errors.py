from __future__ import absolute_import


class AriaAclError(Exception):
    pass


class AriaAclNotFound(AriaAclError):
    pass


class AriaAclValidationError(AriaAclError):
    pass


class AriaAclConflictError(AriaAclError):
    pass
