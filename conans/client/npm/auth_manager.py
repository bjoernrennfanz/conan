from conans.errors import ForbiddenException, AuthenticationException


class NpmAuthManager(object):

    def __init__(self, npm_client_factory, user_io, localdb):
        self._user_io = user_io
        self._npm_client_factory = npm_client_factory
        self._localdb = localdb

    def call_rest_api_method(self, remote, method_name, *args, **kwargs):
        """Handles AuthenticationException and request user to input a user and a password"""
        user = self._localdb.get_username(remote.url)
        npm_client = self._get_npm_client(remote)

        try:
            ret = getattr(npm_client, method_name)(*args, **kwargs)
            return ret
        except ForbiddenException:
            raise ForbiddenException("Permission denied for user: '%s'" % user)
        except AuthenticationException:
            raise ForbiddenException("Authentication failed for user: '%s'" % user)

    def _get_npm_client(self, remote):
        return self._npm_client_factory.new(remote, self._localdb)
