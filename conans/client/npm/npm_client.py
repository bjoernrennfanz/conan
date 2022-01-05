from conans.client.npm.npm_client_v1 import NpmClientV1Methods


class NpmClientFactory(object):

    def __init__(self, output, config, artifacts_properties=None):
        self._output = output
        self._config = config
        self._artifacts_properties = artifacts_properties
        self._cached_capabilities = {}

    def new(self, remote, local_db, api_version=1):
        tmp = NpmClient(remote, local_db, self._output,
                        self._config, api_version,
                        self._artifacts_properties)
        return tmp


class NpmClient(object):
    """
    Rest Api Client for handle remote.
    """

    def __init__(self, remote, local_db, output, config, api_version, artifacts_properties=None):
        # Set to instance
        self._remote = remote
        self._local_db = local_db
        self._output = output
        self._config = config
        self._api_version = api_version
        self._artifacts_properties = artifacts_properties
        self._revisions_enabled = config.revisions_enabled

    def _get_api(self):
        if self._api_version == 1:
            return NpmClientV1Methods(
                self._remote,
                self._local_db,
                self._output,
                self._config,
                self._artifacts_properties
            )
        else:
            raise RuntimeError("Api Version v{} is not implemented, yet.")

    def get_recipe_manifest(self, ref):
        return self._get_api().get_recipe_manifest(ref)

    def get_package_manifest(self, pref):
        return self._get_api().get_package_manifest(pref)

    def get_package_info(self, pref, headers):
        return self._get_api().get_package_info(pref, headers=headers)

    def get_recipe(self, ref, dest_folder):
        return self._get_api().get_recipe(ref, dest_folder)

    def get_recipe_snapshot(self, ref):
        return self._get_api().get_recipe_snapshot(ref)

    def get_recipe_sources(self, ref, dest_folder):
        return self._get_api().get_recipe_sources(ref, dest_folder)

    def get_package(self, pref, dest_folder):
        return self._get_api().get_package(pref, dest_folder)

    def get_package_snapshot(self, ref):
        return self._get_api().get_package_snapshot(ref)

    def get_recipe_path(self, ref, path):
        return self._get_api().get_recipe_path(ref, path)

    def get_package_path(self, pref, path):
        return self._get_api().get_package_path(pref, path)

    def upload_recipe(self, ref, files_to_upload, deleted, retry, retry_wait):
        return self._get_api().upload_recipe(ref, files_to_upload, deleted, retry, retry_wait)

    def upload_package(self, pref, files_to_upload, deleted, retry, retry_wait):
        return self._get_api().upload_package(pref, files_to_upload, deleted, retry, retry_wait)

    def authenticate(self, user, password):
        return self._get_api().authenticate(user, password)

    def check_credentials(self):
        return self._get_api().check_credentials()

    def search(self, pattern=None, ignorecase=True):
        return self._get_api().search(pattern, ignorecase)

    def search_packages(self, reference, query):
        return self._get_api().search_packages(reference, query)

    def remove_recipe(self, ref):
        return self._get_api().remove_conanfile(ref)

    def remove_packages(self, ref, package_ids=None):
        return self._get_api().remove_packages(ref, package_ids)

    def server_capabilities(self):
        return self._get_api().server_capabilities()

    def get_recipe_revisions(self, ref):
        return self._get_api().get_recipe_revisions(ref)

    def get_package_revisions(self, pref):
        return self._get_api().get_package_revisions(pref)

    def get_latest_recipe_revision(self, ref):
        return self._get_api().get_latest_recipe_revision(ref)

    def get_latest_package_revision(self, pref, headers):
        return self._get_api().get_latest_package_revision(pref, headers=headers)
