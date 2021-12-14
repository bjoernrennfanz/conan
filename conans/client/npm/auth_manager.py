

class NpmAuthManager(object):

    def __init__(self, azure_client_factory, user_io, localdb):
        self._azure_client_factory = azure_client_factory
        self._user_io = user_io
        self._localdb = localdb

    def call_rest_api_method(self, remote, method_name, *args, **kwargs):
        """
        Handles AuthenticationException and request user to input a user and a password
        """
        azure_client = self._get_azure_client(remote)
        ret = getattr(azure_client, method_name)(*args, **kwargs)
        return ret

    def _get_azure_client(self, remote):
        return self._azure_client_factory.new(remote, self._localdb, 1)


# if __name__ == "__main__":
# ---------------------------
# Sample Code Npm download:
# ---------------------------
#     from azure.devops.connection import Connection
#     from msrest.authentication import BasicAuthentication
#
#     # Fill in with your personal access token and org URL
#     personal_access_token = 'PAT'
#     feed_url = 'URL'
#
#     # Extract data from given url
#     feed_url_parts = feed_url.split('/')
#     if len(feed_url_parts) < 6:
#         RuntimeError("Cannot parse Organization or Package from given url")
#     elif feed_url_parts[2].find('dev.azure.com') == -1:
#         RuntimeError("Cannot handle platform not equal to dev.azure.com")
#     elif feed_url_parts[6] != 'npm':
#         RuntimeError("Cannot handle packages with given type not equal to npm")
#
#     organization = feed_url_parts[3]
#     organization_url_len = feed_url.find(organization) + len(organization)
#     organization_url = feed_url[:organization_url_len]
#     feed_id = feed_url_parts[5]
#
#     # Create a connection to the org
#     credentials = BasicAuthentication('', personal_access_token)
#     connection = Connection(base_url=organization_url, creds=credentials)
#
#     # Authenticate the connection
#     connection.authenticate()
#
#     # Get packages from feed
#     feed_client = connection.clients_v6_0.get_feed_client()
#     feed_packages = feed_client.get_packages(feed_id, package_name_query='PACKAGE_NAME')
#
#     # Download package
#     npm_client = connection.clients_v6_0.get_npm_client()
#     npm_download_generator = npm_client.get_content_unscoped_package(
#         feed_id,
#         feed_packages[0].name,
#         feed_packages[0].versions[0].version
#     )
#     print('Download started:')
#     with open(feed_packages[0].name + '.targz', 'wb') as file:
#         for chunk in npm_download_generator:
#             print('.')
#             file.write(chunk)
#     print('Download finished')
# ---------------------------
# Sample Code Nuget download:
# ---------------------------
# from azure.devops.connection import Connection
# from msrest.authentication import BasicAuthentication
#
# # Fill in with your personal access token and org URL
# personal_access_token = 'PAT'
# feed_url = 'URL'
#
# # Extract data from given url
# feed_url_parts = feed_url.split('/')
# if len(feed_url_parts) < 6:
#     RuntimeError("Cannot parse Organization or Package from given url")
# elif feed_url_parts[2].find('dev.azure.com') == -1:
#     RuntimeError("Cannot handle platform not equal to dev.azure.com")
# elif feed_url_parts[6] != 'npm':
#     RuntimeError("Cannot handle packages with given type not equal to npm")
#
# organization = feed_url_parts[3]
# organization_url_len = feed_url.find(organization) + len(organization)
# organization_url = feed_url[:organization_url_len]
# feed_id = feed_url_parts[5]
#
# # Create a connection to the org
# credentials = BasicAuthentication('', personal_access_token)
# connection = Connection(base_url=organization_url, creds=credentials)
#
# # Authenticate the connection
# connection.authenticate()
#
# # Get packages from feed
# feed_client = connection.clients_v6_0.get_feed_client()
# feed_packages = feed_client.get_packages(feed_id, package_name_query='PACKAGE_NAME')
#
# # Download package
# nuget_client = connection.clients_v6_0.get_nuget_client()
# nuget_download_generator = nuget_client.download_package(
#     feed_id,
#     feed_packages[0].name,
#     feed_packages[0].versions[0].version
# )
# with open(feed_packages[0].name + '.nupkg', 'wb') as file:
#     for chunk in nuget_download_generator:
#         file.write(chunk)

