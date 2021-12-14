import base64
from itertools import cycle

from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication

from conans.client.cmd.user import update_localdb
from conans.errors import AuthenticationException, ConanException


class NpmClientV1Methods(object):

    def __init__(self, remote, local_db, output, config, artifacts_properties=None):
        # Set to instance
        self._local_db = local_db
        self._remote = remote
        self._output = output
        self._connection = None

        self._artifacts_properties = artifacts_properties
        self._revisions_enabled = config.revisions_enabled
        self._config = config

    def get_recipe_manifest(self, ref):
        raise RuntimeError('Not implemented, yet')

    def get_package_manifest(self, pref):
        raise RuntimeError('Not implemented, yet')

    def get_package_info(self, pref, headers):
        raise RuntimeError('Not implemented, yet')

    def get_recipe(self, ref, dest_folder):
        raise RuntimeError('Not implemented, yet')

    def get_recipe_snapshot(self, ref):
        raise RuntimeError('Not implemented, yet')

    def get_recipe_sources(self, ref, dest_folder):
        raise RuntimeError('Not implemented, yet')

    def get_package(self, pref, dest_folder):
        raise RuntimeError('Not implemented, yet')

    def get_package_snapshot(self, ref):
        raise RuntimeError('Not implemented, yet')

    def get_recipe_path(self, ref, path):
        raise RuntimeError('Not implemented, yet')

    def get_package_path(self, pref, path):
        raise RuntimeError('Not implemented, yet')

    def upload_recipe(self, ref, files_to_upload, deleted, retry, retry_wait):
        raise RuntimeError('Not implemented, yet')

    def upload_package(self, pref, files_to_upload, deleted, retry, retry_wait):
        raise RuntimeError('Not implemented, yet')

    def authenticate(self, user, password):
        if user is None:  # The user is already in DB, just need the password
            prev_user = self._localdb.get_username(self._remote.url)
            if prev_user is None:
                raise ConanException("User for remote '%s' is not defined" % self._remote.name)
            else:
                user = prev_user

        # Extract data from given url
        remote_url = self._remote.url
        remote_url_parts = remote_url.split('/')
        if len(remote_url_parts) < 6:
            ConanException("Cannot parse Organization or Package from given url")
        elif remote_url_parts[2].find('dev.azure.com') == -1:
            ConanException("Cannot handle platform not equal to dev.azure.com")
        elif remote_url_parts[6] != 'npm':
            ConanException("Cannot handle packages with given type not equal to npm")

        organization = remote_url_parts[3]
        organization_url_len = remote_url.find(organization) + len(organization)
        organization_url = remote_url[:organization_url_len]

        # Create a connection to the org
        credentials = BasicAuthentication(user, password)
        connection = Connection(base_url=organization_url, creds=credentials)

        # Authenticate the connection
        try:
            connection.authenticate()
        except Exception as ex:
            raise AuthenticationException(ex)

        # Generate token
        token_raw_bytes = password.encode()
        token_bytes = base64.b64encode(token_raw_bytes)

        # Store result in DB
        remote_name, prev_user, user = update_localdb(self._local_db, user,
                                                      token_bytes.decode(),
                                                      self._sxor(user, password),
                                                      self._remote)

        return remote_name, prev_user, user

    def check_credentials(self):
        raise RuntimeError('Not implemented, yet')

    def search(self, pattern=None, ignorecase=True):
        raise RuntimeError('Not implemented, yet')

    def search_packages(self, reference, query):
        raise RuntimeError('Not implemented, yet')

    def remove_recipe(self, ref):
        raise RuntimeError('Not implemented, yet')

    def remove_packages(self, ref, package_ids=None):
        raise RuntimeError('Not implemented, yet')

    def server_capabilities(self):
        raise RuntimeError('Not implemented, yet')

    def get_recipe_revisions(self, ref):
        raise RuntimeError('Not implemented, yet')

    def get_package_revisions(self, pref):
        raise RuntimeError('Not implemented, yet')

    def get_latest_recipe_revision(self, ref):
        raise RuntimeError('Not implemented, yet')

    def get_latest_package_revision(self, pref, headers):
        raise RuntimeError('Not implemented, yet')

    @staticmethod
    def _sxor(s1, s2):
        """ XOR two byte strings """
        zip_list = zip(s1, cycle(s2)) if len(s1) > len(s2) else zip(cycle(s1), s2)
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip_list)
