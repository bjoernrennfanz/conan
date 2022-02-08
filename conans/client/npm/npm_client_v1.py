import base64
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
from itertools import cycle
from pathlib import Path

from azure.devops.connection import Connection
from conans.model.ref import ConanFileReference
from msrest.authentication import BasicAuthentication

from conans.client.cmd.user import update_localdb
from conans.client.remote_manager import check_compressed_files
from conans.errors import AuthenticationException, ConanException, \
    NoRestV2Available, NotFoundException
from conans.model.info import ConanInfo
from conans.model.manifest import FileTreeManifest
from conans.paths import CONAN_MANIFEST, EXPORT_SOURCES_TGZ_NAME, EXPORT_TGZ_NAME, PACKAGE_TGZ_NAME, \
    CONANINFO
from conans.tools import untargz
from conans.util.files import decode_text, md5sum


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

        # Create download cache for conan-npm packages
        self._npm_cache = os.path.join(Path.home(), '.conan-npm')
        if not os.path.exists(self._npm_cache):
            os.mkdir(self._npm_cache)

    def _download_recipe_npm(self, ref):
        npm_name = ref.name + '-recipe'

        files = self._download_npm(npm_name, ref.version, ref.revision)
        return files

    def _download_package_npm(self, pref):
        npm_ref = pref.ref
        npm_name = npm_ref.name + '-' + pref.id

        files = self._download_npm(npm_name, npm_ref.version, npm_ref.revision)
        return files

    def _download_npm(self, npm_name, version, revision):
        """ Downloads the npm package from azure feed """
        # Get npm package version
        revision = revision if revision else "0"
        npm_version = self._get_npm_version(version, revision)

        # Build npm cache path
        npm_package_path = os.path.join(self._npm_cache, 'packages', npm_name, npm_version)
        npm_package_file = os.path.join(npm_package_path, npm_name + '.tgz')

        # Check if already downloaded
        if not os.path.isfile(npm_package_file):
            self.check_credentials()
            _, feed_id = self._get_organization_url_and_feed(self._remote)

            # Find correct feed_project
            feed_project = None
            feed_client = self._connection.clients_v6_0.get_feed_client()
            feeds = feed_client.get_feeds()
            for feed in feeds:
                if feed.name == feed_id:
                    feed_project = feed.project
                    if feed_project:
                        feed_project = feed.project.id
                    break

            # Check for npm package hits
            feed_packages = feed_client.get_packages(feed_id, project=feed_project, package_name_query=npm_name, include_all_versions=True)
            if not feed_packages:
                raise NotFoundException(("No packages found matching pattern '%s'" % npm_name))

            # Find correct version
            npm_package = None
            npm_package_version = None
            for feed_package in feed_packages:
                for feed_package_version in feed_package.versions:
                    # Check of versions matches
                    if feed_package_version.normalized_version == npm_version:
                        npm_package = feed_package
                        npm_package_version = feed_package_version.normalized_version
                        break
                    # Alternative fall back to latest version
                    if feed_package_version.is_latest and revision == "0":
                        npm_package = feed_package
                        npm_package_version = feed_package_version.normalized_version
                        break
                if npm_package and npm_package_version:
                    break

            if not npm_package_version:
                raise NotFoundException(("No packages found matching version '%s'" % npm_version))

            # Update paths and file names
            npm_package_path = os.path.join(self._npm_cache, 'packages', npm_package.name, npm_package_version)
            npm_package_file = os.path.join(npm_package_path, npm_package.name + '.tgz')

            # Check again file exists
            if not os.path.isfile(npm_package_file):
                # Download package
                npm_client = self._connection.clients_v6_0.get_npm_client()
                npm_download_generator = npm_client.get_content_unscoped_package(
                    feed_id,
                    npm_package.name,
                    npm_package_version,
                    project=feed_project
                )

                if self._output and not self._output.is_terminal:
                    self._output.writeln("Downloading npm package '%s/%s'..." % (npm_package.name, npm_package_version))

                os.makedirs(npm_package_path, exist_ok=True)
                with open(npm_package_file, 'wb') as file:
                    for chunk in npm_download_generator:
                        file.write(chunk)

        # Extract downloaded file
        npm_package_content_path = os.path.join(npm_package_path, "package")
        if not os.path.exists(npm_package_content_path):
            untargz(npm_package_file, npm_package_path)

        # Get all files from cache
        found_files = [fn for fn in glob.glob(npm_package_content_path + os.path.sep + "**", recursive=True)
                       if not os.path.basename(fn).startswith('package.json') and os.path.isfile(fn)]

        # Convert to dict
        files = {}
        for found_file in found_files:
            files[os.path.basename(found_file)] = found_file

        return files

    def _get_file_contents(self, files, filters):
        contents = {}
        for filename, filepath in files.items():
            if filename in filters:
                with open(filepath, 'rb') as handle:
                    file_content = handle.read()
                contents[filename] = file_content

        return contents

    def _copy_files_to_folder(self, src_files, dest_folder):
        copied_files = {}
        for src_filename, src_filepath in src_files.items():
            # Copy file to dest_folder
            dest_filepath = os.path.join(dest_folder, src_filename)
            os.makedirs(os.path.dirname(dest_filepath), exist_ok=True)
            shutil.copyfile(src_filepath, dest_filepath)

            # Add copied file to dict
            copied_files[src_filename] = dest_filepath

        return copied_files

    def get_recipe_manifest(self, ref):
        """Gets a FileTreeManifest from conans"""
        # Obtain the files from npm package
        npm_package_files = self._download_recipe_npm(ref)
        contents = self._get_file_contents(npm_package_files, [CONAN_MANIFEST])

        # Unroll generator and decode (plain text)
        contents = {key: decode_text(value) for key, value in contents.items()}
        return FileTreeManifest.loads(contents[CONAN_MANIFEST])

    def get_package_manifest(self, pref):
        """Gets a FileTreeManifest from a package"""
        pref = pref.copy_with_revs(None, None)
        # Obtain the files from npm package
        npm_package_files = self._download_package_npm(pref)
        contents = self._get_file_contents(npm_package_files, [CONAN_MANIFEST])

        # Unroll generator and decode (plain text)
        contents = {key: decode_text(value) for key, value in contents.items()}
        return FileTreeManifest.loads(contents[CONAN_MANIFEST])

    def get_package_info(self, pref, headers):
        """Gets a ConanInfo file from a package"""
        pref = pref.copy_with_revs(None, None)
        # Obtain the files from npm package
        npm_package_files = self._download_package_npm(pref)

        if CONANINFO not in npm_package_files:
            raise NotFoundException("Package %s doesn't have the %s file!" % (pref, CONANINFO))

        # Get the info (in memory)
        contents = self._get_file_contents(npm_package_files, [CONANINFO])

        # Unroll generator and decode (plain text)
        contents = {key: decode_text(value) for key, value in dict(contents).items()}
        return ConanInfo.loads(contents[CONANINFO])

    def get_recipe(self, ref, dest_folder):
        npm_package_files = self._download_recipe_npm(ref)
        npm_package_files.pop(EXPORT_SOURCES_TGZ_NAME, None)
        check_compressed_files(EXPORT_TGZ_NAME, npm_package_files)

        # Copy files from cache to dest_folder
        recipe_files = self._copy_files_to_folder(npm_package_files, dest_folder)
        return recipe_files

    def get_recipe_snapshot(self, ref):
        try:
            # Get the digest and calculate md5 of package files
            npm_package_files = self._download_recipe_npm(ref)
            snapshot = {}
            for src_filename, src_filepath in npm_package_files.items():
                snapshot[src_filename] = md5sum(src_filepath)
        except NotFoundException:
            snapshot = []
        return snapshot

    def get_recipe_sources(self, ref, dest_folder):
        npm_package_files = self._download_recipe_npm(ref)
        check_compressed_files(EXPORT_SOURCES_TGZ_NAME, npm_package_files)
        if EXPORT_SOURCES_TGZ_NAME not in npm_package_files:
            return None

        npm_package_files = {EXPORT_SOURCES_TGZ_NAME: npm_package_files[EXPORT_SOURCES_TGZ_NAME]}

        # Copy files from cache to dest_folder
        recipe_sources_files = self._copy_files_to_folder(npm_package_files, dest_folder)
        return recipe_sources_files

    def get_package(self, pref, dest_folder):
        npm_package_files = self._download_package_npm(pref)
        check_compressed_files(PACKAGE_TGZ_NAME, npm_package_files)

        # Copy files from cache to dest_folder
        package_files = self._copy_files_to_folder(npm_package_files, dest_folder)
        return package_files

    def get_package_snapshot(self, pref):
        try:
            # Get the digest and calculate md5 of package files
            npm_package_files = self._download_package_npm(pref)
            snapshot = {}
            for src_filename, src_filepath in npm_package_files.items():
                snapshot[src_filename] = md5sum(src_filepath)
        except NotFoundException:
            snapshot = []
        return snapshot

    def _get_path(self, npm_package_files, path):
        files = npm_package_files.keys()

        def is_dir(the_path):
            if the_path == ".":
                return True
            for _the_file in files:
                if the_path == _the_file:
                    return False
                elif _the_file.startswith(the_path):
                    return True
            raise NotFoundException("The specified path doesn't exist")

        if is_dir(path):
            ret = []
            for the_file in files:
                if path == "." or the_file.startswith(path):
                    tmp = the_file[len(path) - 1:].split("/", 1)[0]
                    if tmp not in ret:
                        ret.append(tmp)
            return sorted(ret)
        else:
            contents = self._get_file_contents(npm_package_files, [path])
            content = contents[path]

            return decode_text(content)

    def get_recipe_path(self, ref, path):
        """Gets a file content or a directory list"""
        npm_package_files = self._download_recipe_npm(ref)
        return self._get_path(npm_package_files, path)

    def get_package_path(self, pref, path):
        """Gets a file content or a directory list"""
        npm_package_files = self._download_package_npm(pref)
        return self._get_path(npm_package_files, path)

    def upload_recipe(self, ref, files_to_upload, deleted, retry, retry_wait):
        npm_name = ref.name + '-recipe'
        self._upload_as_npm(npm_name, ref.version, ref.revision, files_to_upload, deleted, retry, retry_wait)

    def upload_package(self, pref, files_to_upload, deleted, retry, retry_wait):
        npm_ref = pref.ref
        npm_name = npm_ref.name + '-' + pref.id
        self._upload_as_npm(npm_name, npm_ref.version, npm_ref.revision, files_to_upload, deleted, retry, retry_wait)

    def _upload_as_npm(self, npm_name, version, revision, files_to_upload, deleted, retry, retry_wait):
        self.check_credentials()
        user, token, refresh_token = self._local_db.get_login(self._remote.url)

        # Get npm package version
        npm_version = self._get_npm_version(version, revision)

        with tempfile.TemporaryDirectory() as tmp_dir_name:
            remote_url = self._remote.url
            remote_url_no_https = remote_url.replace('https:', '')
            remote_url_no_https_and_registry = remote_url_no_https.replace('registry/', '')

            # Create .npmrc file
            npmrc = os.path.join(os.path.abspath(tmp_dir_name), '.npmrc')
            npmrc_file = open(npmrc, "w", encoding='utf8')
            npmrc_file.write(('registry = %s\n' % self._remote.url))
            npmrc_file.write('always-auth = true\n')
            npmrc_file.write('; begin auth token\n')
            npmrc_file.write(('%s:username=%s\n' % (remote_url_no_https, user)))
            npmrc_file.write(('%s:_password=%s\n' % (remote_url_no_https, token)))
            npmrc_file.write(('%s:email=npm requires email to be set but doesn\'t use the value\n' % remote_url_no_https))
            npmrc_file.write(('%s:username=%s\n' % (remote_url_no_https_and_registry, user)))
            npmrc_file.write(('%s:_password=%s\n' % (remote_url_no_https_and_registry, token)))
            npmrc_file.write(('%s:email=npm requires email to be set but doesn\'t use the value\n' % remote_url_no_https_and_registry))
            npmrc_file.write('; end auth token\n')
            npmrc_file.close()

            # Create package.json
            package_json_data = {
                "name": npm_name,
                "description": npm_name + " package created by conan.io",
                "version": npm_version,
            }

            package_json = os.path.join(tmp_dir_name, 'package.json')
            package_json_file = open(package_json, "w", encoding='utf8')
            package_json_file.write(json.dumps(package_json_data, sort_keys=True, ensure_ascii=False))
            package_json_file.close()

            # Copy needed files
            for filename, filepath in files_to_upload.items():
                shutil.copyfile(filepath, os.path.join(tmp_dir_name, filename))

            # Run NPM publish
            subprocess.run("npm publish", shell=True, cwd=tmp_dir_name)

    def _get_npm_version(self, version, revision):
        # Convert to valid npm version
        npm_version_build_number = None
        npm_version_tokens = version.split(".")
        if len(npm_version_tokens) > 3:
            npm_version_build_number = npm_version_tokens.pop()

        # Build npm version
        npm_version = ".".join(npm_version_tokens)

        # Check version is semantic 2.0 compatible
        match = re.match("^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
                          "(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
                          "(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))"
                          "?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$", npm_version)
        if not match:
            npm_version = "1.0.0-conan-" + npm_version

        if revision and revision != "0":
            npm_version += "-" + revision
            if npm_version_build_number:
                npm_version += "." + npm_version_build_number
        else:
            if npm_version_build_number:
                npm_version += "-" + npm_version_build_number

        return npm_version

    def _get_organization_url_and_feed(self, remote):
        # Extract data from given url
        remote_url = remote.url
        remote_url_parts = remote_url.split('/')
        if len(remote_url_parts) < 6:
            ConanException("Cannot parse Organization or Package from given url")
        if remote_url_parts[2].find('dev.azure.com') == -1:
            ConanException("Cannot handle platform not equal to dev.azure.com")

        # Find npm keyword in remote url
        npm_pos = 0
        npm_index = 0
        for remote_url_part in remote_url_parts:
            if 'npm' == remote_url_part:
                npm_pos = npm_index
                break
            npm_index += 1

        # Check npm keyword was found
        if npm_pos == 0:
            ConanException("Cannot handle packages with given type not equal to npm")

        organization = remote_url_parts[3]
        organization_url_len = remote_url.find(organization) + len(organization)

        return remote_url[:organization_url_len], remote_url_parts[npm_pos - 1]

    def authenticate(self, user, password):
        if user is None:  # The user is already in DB, just need the password
            prev_user = self._localdb.get_username(self._remote.url)
            if prev_user is None:
                raise ConanException("User for remote '%s' is not defined" % self._remote.name)
            else:
                user = prev_user

        # Create a connection to the org
        organization_url, _ = self._get_organization_url_and_feed(self._remote)
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
        organization_url, _ = self._get_organization_url_and_feed(self._remote)
        user, token, refresh_token = self._local_db.get_login(self._remote.url)
        if not user or not refresh_token:
            raise AuthenticationException('Username or password not valid.')

        # Decrypt password
        password = self._sxor(user, refresh_token)

        # Create a connection to the org
        credentials = BasicAuthentication(user, password)
        self._connection = Connection(base_url=organization_url, creds=credentials)

        # Authenticate the connection
        try:
            self._connection.authenticate()
        except Exception as ex:
            raise AuthenticationException(ex)

    def search(self, pattern=None, ignorecase=True):
        self.check_credentials()
        _, feed_id = self._get_organization_url_and_feed(self._remote)

        # Find correct feed_project
        feed_project = None
        feed_client = self._connection.clients_v6_0.get_feed_client()
        feeds = feed_client.get_feeds()
        for feed in feeds:
            if feed.name == feed_id:
                feed_project = feed.project
                if feed_project:
                    feed_project = feed.project.id
                break

        # Check for npm package hits
        search_results = []
        pattern, _ = self._split_pair(pattern, "/") or (pattern, None)
        feed_packages = feed_client.get_packages(
            feed_id, project=feed_project, package_name_query=pattern,
            include_all_versions=True
        )
        for feed_package in feed_packages:
            if '-recipe' in feed_package.normalized_name:
                conan_package_name = feed_package.normalized_name.replace(
                    '-recipe', ''
                )

                for feed_package_version in feed_package.versions:
                    npm_package_version = feed_package_version.normalized_version

                    # Remove non semantic version extension form npm version
                    npm_package_version = npm_package_version.replace(
                        '1.0.0-conan-', ''
                    )

                    version, revision_build = self._split_pair(npm_package_version, '-') \
                        or (npm_package_version, None)
                    revision, build = self._split_pair(revision_build, '.') \
                        or (None, revision_build)

                    conan_package = conan_package_name + '/' + version
                    conan_package = conan_package + ('.' + build) if build else conan_package
                    conan_package = conan_package + '@_/_'
                    conan_package = conan_package + ('#' + revision) if revision else conan_package

                    search_results.append(conan_package)

        return [ConanFileReference.loads(reference) for reference in search_results]

    def search_packages(self, reference, query):
        self.check_credentials()
        raise RuntimeError('Not implemented, yet')

    def remove_recipe(self, ref):
        self.check_credentials()
        raise RuntimeError('Not implemented, yet')

    def remove_packages(self, ref, package_ids=None):
        self.check_credentials()
        raise RuntimeError('Not implemented, yet')

    def server_capabilities(self):
        raise RuntimeError('Not implemented, yet')

    def get_recipe_revisions(self, ref):
        raise NoRestV2Available("The remote doesn't support revisions")

    def get_package_revisions(self, pref):
        raise NoRestV2Available("The remote doesn't support revisions")

    def get_latest_recipe_revision(self, ref):
        raise NoRestV2Available("The remote doesn't support revisions")

    def get_latest_package_revision(self, pref, headers):
        raise NoRestV2Available("The remote doesn't support revisions")

    def _sxor(self, s1, s2):
        """ XOR two byte strings """
        zip_list = zip(s1, cycle(s2)) if len(s1) > len(s2) else zip(cycle(s1), s2)
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip_list)

    def _split_pair(self, pair, split_char):
        if not pair or pair == split_char:
            return None, None
        if split_char not in pair:
            return None

        words = pair.split(split_char)
        if len(words) != 2:
            raise ConanException("The reference has too many '{}'".format(split_char))
        else:
            return words
