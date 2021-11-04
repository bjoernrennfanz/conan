
class NuGetAuthManager(object):

    def __init__(self, user_io, localdb):
        self._user_io = user_io
        self._localdb = localdb

    def call_rest_api_method(self, remote, method_name, *args, **kwargs):
        """Handles AuthenticationException and request user to input a user and a password"""
        user, token, refresh_token = self._localdb.get_login(remote.url)
        # rest_client = self._get_rest_client(remote)

        if method_name == "authenticate":
            return self._authenticate(remote, *args, **kwargs)
