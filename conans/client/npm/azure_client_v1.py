from azure.devops.connection import Connection
from msrest.authentication import BasicAuthentication
from conans.errors import AuthenticationException, ConanException, ForbiddenException


class AzureV1Methods(object):

    def __init__(self, remote, local_db, output, config, api_version, artifacts_properties=None):
        # Set to instance
        self._local_db = local_db
        self._remote = remote
        self._output = output
        self._connection = None

        self._artifacts_properties = artifacts_properties
        self._revisions_enabled = config.revisions_enabled
        self._config = config
        self._api_version = api_version

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

    def authenticate(self, user, password=None):
        remote_url = self._remote.url
        remote_name = self._remote.name
        # Load remote data from local db cache
        db_user, db_token, db_refresh_token = self._local_db.get_login(remote_url)
        previous_user = db_user
        # Extract data from given url
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
        # If given password is None, try to connect with stored credentials form local database
        pat = (password, db_token)[password is None]
        # Create a connection to the org
        credentials = BasicAuthentication('', pat)
        connection = Connection(base_url=organization_url, creds=credentials)
        # Authenticate the connection
        try:
            connection.authenticate()
        except Exception as ex:
            raise AuthenticationException(ex)
        # Store connection and credentials if they are new
        self._connection = connection
        if password is not None:
            self._store_user_token_in_db(user, pat, None, self._remote)
        return remote_name, previous_user, user

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

    def _store_user_token_in_db(self, user, token, refresh_token, remote):
        try:
            self._local_db.store(user, token, refresh_token, remote_url=remote.url)
        except Exception as e:
            self._output.error('Your credentials could not be stored in local cache\n')
            self._output.debug(str(e) + '\n')

    def _clear_user_tokens_in_db(self, user, remote):
        try:
            self._local_db.store(user, token=None, refresh_token=None, remote_url=remote.url)
        except Exception as e:
            self._output.error('Your credentials could not be stored in local cache\n')
            self._output.debug(str(e) + '\n')

