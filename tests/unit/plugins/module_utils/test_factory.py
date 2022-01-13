import os
import tempfile
import unittest
from tpm import TpmApiv4
from unittest_data_provider import data_provider
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.factory import (
    TpmApiFactory,
    TeamPasswordManagerFactory,
    ENV_VARIABLE_TPM_CONFIGURATION,
    ENV_VARIABLE_TPM_CONFIGURATION_FILE_PATH,
)
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager import (
    TeamPasswordManager,
    CachingTeamPasswordManager
)

CONFIG_SECTION_SIMPLE = 'auth:simple'
CONFIG_SECTION_HMAC = 'auth:hmac'

TPM_BASIC_CONFIG_EXAMPLE = '''
[%s]
hmac        = False
url         = https://teampasswordmanager.com
username    = deploy
password    = secret

[%s]
hmac        = True
url         = https://teampasswordmanager.com
public_key  = my_public_key
private_key = my_private_key
''' % (CONFIG_SECTION_SIMPLE, CONFIG_SECTION_HMAC)

class TestTpmApiFactory(unittest.TestCase):
    def setUp(self):
        self.setup_env_variable_file_path_case()
        self.setup_env_variable_case()

    def tearDown(self):
        self.tear_down_env_variable_file_path_case()
        self.tear_down_env_variable_case()

    def setup_env_variable_case(self):
        os.environ[ENV_VARIABLE_TPM_CONFIGURATION] = TPM_BASIC_CONFIG_EXAMPLE

    def setup_env_variable_file_path_case(self):
        file_name = tempfile.mkstemp('team_password_manager')[1]

        with open(file_name, "w", encoding='utf-8') as file:
            file.write(TPM_BASIC_CONFIG_EXAMPLE)

        self._tpm_file_name = file_name
        os.environ[ENV_VARIABLE_TPM_CONFIGURATION_FILE_PATH] = file_name

    def tear_down_env_variable_file_path_case(self):
        if os.path.isfile(self._tpm_file_name):
            os.remove(self._tpm_file_name)

        if ENV_VARIABLE_TPM_CONFIGURATION_FILE_PATH in os.environ:
            del os.environ[ENV_VARIABLE_TPM_CONFIGURATION_FILE_PATH]

    def tear_down_env_variable_case(self):
        if ENV_VARIABLE_TPM_CONFIGURATION in os.environ:
            del os.environ[ENV_VARIABLE_TPM_CONFIGURATION]

    def test_create_from_create_from_file(self):
        api = (TpmApiFactory()).create_from_file(CONFIG_SECTION_SIMPLE)
        self.assert_api_data(api, False)

        api = (TpmApiFactory()).create_from_file(CONFIG_SECTION_HMAC)
        self.assert_api_data(api, True)

    def test_create_simple(self):
        self.assert_create(CONFIG_SECTION_SIMPLE)

    def test_create_hmac(self):
        self.assert_create(CONFIG_SECTION_HMAC)

    def assert_create(self, section: str):
        is_hmac = section is CONFIG_SECTION_HMAC

        api = (TpmApiFactory()).create(section)
        self.assert_api_data(api, is_hmac)
        del os.environ[ENV_VARIABLE_TPM_CONFIGURATION]

        api = (TpmApiFactory()).create(section)
        self.assert_api_data(api, is_hmac)
        del os.environ[ENV_VARIABLE_TPM_CONFIGURATION_FILE_PATH]

        with self.assertRaises(Exception):
            (TpmApiFactory()).create(section)

    def test_create_from_env_variable(self):
        api = (TpmApiFactory()).create_from_env_variable(CONFIG_SECTION_SIMPLE)
        self.assert_api_data(api, False)

        api = (TpmApiFactory()).create_from_env_variable(CONFIG_SECTION_HMAC)
        self.assert_api_data(api, True)

    def assert_api_data(self, api: TpmApiv4, is_hmac: bool):
        self.assertEqual('https://teampasswordmanager.com/index.php/api/v4/', api.url)

        if is_hmac is False:
            self.assertEqual('deploy', api.username)
            self.assertEqual('secret', api.password)
            self.assertEqual(False, api.private_key)
            self.assertEqual(False, api.public_key)
        else:
            self.assertEqual(False, api.username)
            self.assertEqual(False, api.password)
            self.assertEqual('my_private_key', api.private_key)
            self.assertEqual('my_public_key', api.public_key)

def create_data_provider():
    return (
        (
            '''
[auth:test]
hmac     = False
url      = https://teampasswordmanager.com
username = deploy
password = secret
            ''',
            TeamPasswordManager,
        ),
        (
            '''
[auth:test]
hmac     = False
url      = https://teampasswordmanager.com
username = deploy
password = secret
cache_ttl = 200
            ''',
            TeamPasswordManager,
        ),
        (
            '''
[auth:test]
hmac                 = False
url                  = https://teampasswordmanager.com
username             = deploy
password             = secret
cache_encryption_key = 9be220f0470b4da3729eadb79c641506ce1502c3428c5d996c8b7c3772af9387
cache_ttl            = 200
            ''',
            CachingTeamPasswordManager,
        ),
        (
            '''
[auth:test]
hmac                 = False
url                  = https://teampasswordmanager.com
username             = deploy
password             = secret
cache_encryption_key = 9be220f0470b4da3729eadb79c641506ce1502c3428c5d996c8b7c3772af9387
            ''',
            CachingTeamPasswordManager,
        ),
    )

class TestTeamPasswordManagerFactory(unittest.TestCase):
    def tearDown(self):
        if ENV_VARIABLE_TPM_CONFIGURATION in os.environ:
            del os.environ[ENV_VARIABLE_TPM_CONFIGURATION]


    @data_provider(create_data_provider)
    def test_create(self, config: str, epxected_instance: type):
        os.environ[ENV_VARIABLE_TPM_CONFIGURATION] = config
        manager = (TeamPasswordManagerFactory()).create("auth:test")
        self.assertIsInstance(manager, epxected_instance)
