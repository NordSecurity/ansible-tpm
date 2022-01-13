# pylint: disable=C0302
# pylint: disable=C0301

from datetime import datetime, timedelta
from typing import List, Union
from unittest.mock import Mock, call, patch
import hashlib
import json
import unittest
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from unittest_data_provider import data_provider
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.entities import (
    Certificate,
    Password,
    TpmCertificate
)
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager import (
    CachingTeamPasswordManager,
    TeamPasswordManager,
    generate_certificate_cache_key,
    generate_password_cache_key,
    generate_get_projects_password_ids_cache_key,
    generate_get_certificate
)

EXAMPLE_PASSWORD_DATA = {
    'custom_field1': {'data': 'password_in_custom_field1'},
    'custom_field2': {'data': 'password_in_custom_field2'},
    'id': 1,
    'name': 'password_name',
    'password': 'password_value',
}

EXAMPLE_PASSWORDS_LIST = {
    1: {
        'id': 1,
        'name': 'password_name_1',
        'password': 'password_value_1',
    },
    2: {
        'id': 2,
        'name': 'password_name_2',
        'password': 'password_value_2',
    },
    10: {
        'id': 10,
        'name': 'password_name_10',
        'password': 'password_value_10',
    }
}

EXAMPLE_PROJECT_LIST_DATA = {
    1: [
        {
            'id': 1,
            'name': 'password_name_1',
        },
        {
            'id': 2,
            'name': 'password_name_2',
        },
    ],
    2: [{'id': 3, 'name': 'password_name_3'}],
    3: [{'id': 10, 'name': 'password_name_10'}],
}

EXAMPLE_CERTIFICATE_DATA = {
    'id': 1,
    'name': 'some_name',
    'custom_field1': {'data': 'cert'},
    'custom_field2': {'data': 'chain'},
    'custom_field3': {'data': 'fullchain'},
    'custom_field4': {'data': 'privkey'},
}


def generate_certificate(not_before: timedelta, not_after: timedelta) -> dict:
    key = crypto.PKey()
    # small key size just to make the tests run faster
    key.generate_key(crypto.TYPE_RSA, 1024)

    cert = crypto.X509()
    cert.gmtime_adj_notBefore(int(not_before.total_seconds()))
    cert.gmtime_adj_notAfter(int(not_after.total_seconds()))
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha512')

    return {
        'certificate': crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"),
        'key': crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"),
    }


class PasswordMatcher:
    expected: Password

    def __init__(self, expected):
        self.expected = expected

    def __repr__(self):
        return repr(self.expected)

    def __eq__(self, other):
        if isinstance(self.expected, type(other)) is False:
            return False

        if self.expected is None:
            return True

        return (self.expected.id == other.id
                and self.expected.name == other.name
                and self.expected.password == other.password)


def get_password_data_provider():
    return (
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
                'password': EXAMPLE_PASSWORD_DATA['password'],
            },
            Password(
                EXAMPLE_PASSWORD_DATA['id'],
                EXAMPLE_PASSWORD_DATA['name'],
                EXAMPLE_PASSWORD_DATA['password']
            )
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
                'custom_field1': EXAMPLE_PASSWORD_DATA['custom_field1'],
            },
            Password(
                EXAMPLE_PASSWORD_DATA['id'],
                EXAMPLE_PASSWORD_DATA['name'],
                EXAMPLE_PASSWORD_DATA['custom_field1']['data']
            )
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
                'custom_field1': EXAMPLE_PASSWORD_DATA['custom_field1'],
                'custom_field2': EXAMPLE_PASSWORD_DATA['custom_field2'],
            },
            Password(
                EXAMPLE_PASSWORD_DATA['id'],
                EXAMPLE_PASSWORD_DATA['name'],
                EXAMPLE_PASSWORD_DATA['custom_field1']['data']
            )
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
                'custom_field1': {'data': ''},
                'custom_field2': {'data': ''},
            },
            None
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
                'custom_field2': EXAMPLE_PASSWORD_DATA['custom_field2'],
            },
            Password(
                EXAMPLE_PASSWORD_DATA['id'],
                EXAMPLE_PASSWORD_DATA['name'],
                EXAMPLE_PASSWORD_DATA['custom_field2']['data']
            )
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
                'custom_field3': EXAMPLE_PASSWORD_DATA['custom_field2'],
            },
            None
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
                'password': '',
            },
            None
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': '',
                'password': EXAMPLE_PASSWORD_DATA['password'],
            },
            None
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'name': EXAMPLE_PASSWORD_DATA['name'],
            },
            None
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
                'password': EXAMPLE_PASSWORD_DATA['password'],
            },
            None
        ),
        (
            {
                'id': EXAMPLE_PASSWORD_DATA['id'],
            },
            None
        ),
    )


def get_passwords_data_provider():
    return (
        (
            EXAMPLE_PASSWORDS_LIST,
            [1, 2],
            [
                Password(1, 'password_name_1', 'password_value_1'),
                Password(2, 'password_name_2', 'password_value_2'),
            ]
        ),
        (
            EXAMPLE_PASSWORDS_LIST,
            [2, 2],
            [
                Password(2, 'password_name_2', 'password_value_2'),
            ],
        ),
        (
            {
                **EXAMPLE_PASSWORDS_LIST,
                **{
                    3: {
                        'id': 3,
                        'name': 'password_name_2',
                        'password': 'password_value_2',
                    }
                },
            },
            [2, 3],
            [
                Password(2, 'password_name_2', 'password_value_2'),
                Password(3, 'password_name_2', 'password_value_2'),
            ],
        ),
        (EXAMPLE_PASSWORDS_LIST, [], []),
        ({}, [], []),
        ({}, [1,2,3], []),
    )


def get_projects_passwords_data_provider():
    return (
        (
            EXAMPLE_PROJECT_LIST_DATA,
            EXAMPLE_PASSWORDS_LIST,
            [1, 2],
            [
                Password(1, 'password_name_1', 'password_value_1'),
                Password(2, 'password_name_2', 'password_value_2'),
            ]
        ),
        (
            EXAMPLE_PROJECT_LIST_DATA,
            EXAMPLE_PASSWORDS_LIST,
            [2],
            []
        ),
        (
            EXAMPLE_PROJECT_LIST_DATA,
            EXAMPLE_PASSWORDS_LIST,
            [1,2,3],
            [
                Password(1, 'password_name_1', 'password_value_1'),
                Password(2, 'password_name_2', 'password_value_2'),
                Password(10, 'password_name_10', 'password_value_10'),
            ]
        ),
        (
            EXAMPLE_PROJECT_LIST_DATA,
            EXAMPLE_PASSWORDS_LIST,
            [1],
            [
                Password(1, 'password_name_1', 'password_value_1'),
                Password(2, 'password_name_2', 'password_value_2'),
            ]
        ),
        (
            EXAMPLE_PROJECT_LIST_DATA,
            EXAMPLE_PASSWORDS_LIST,
            [],
            []
        ),
        (
            EXAMPLE_PROJECT_LIST_DATA,
            {},
            [1],
            []
        ),
        (
            {},
            {},
            [1],
            []
        ),
    )


class TestTeamPasswordManager(unittest.TestCase):
    _tpm_api_mock: Mock
    _team_password_manager: TeamPasswordManager

    def setUp(self):
        self._tpm_api_mock = Mock()
        self._team_password_manager = TeamPasswordManager(self._tpm_api_mock)

    @data_provider(get_password_data_provider)
    def test_get_password(self, show_password_return_value: dict, expected_result: Password):
        self._tpm_api_mock.show_password.return_value = show_password_return_value

        self.assertEqual(
            PasswordMatcher(expected_result),
            self._team_password_manager.get_password(show_password_return_value['id'])
        )

        self._tpm_api_mock.show_password.assert_called_with(show_password_return_value['id'])

    @data_provider(get_passwords_data_provider)
    def test_get_passwords(
            self,
            passwords: dict,
            password_ids: List[int],
            expected_result: List[Password]
    ):
        def password_data_side_effect(password_id: int):
            try:
                return passwords[password_id]
            except KeyError:
                return {}

        self._tpm_api_mock.show_password.side_effect = password_data_side_effect

        result = self._team_password_manager.get_passwords(password_ids)

        self.assertEqual(len(expected_result), len(result))

        for index, password in enumerate(expected_result):
            self.assertEqual(password.id, result[index].id)
            self.assertEqual(password.name, result[index].name)
            self.assertEqual(password.password, result[index].password)

        calls = []

        for password_id in password_ids:
            calls.append(call(password_id))

        self._tpm_api_mock.show_password.assert_has_calls(calls, any_order=True)

    @data_provider(get_projects_passwords_data_provider)
    def test_get_projects_passwords(
            self,
            projects: dict,
            passwords: dict,
            project_ids: List[int],
            expected_passwords: List[Password]
    ):
        def list_passwords_of_project_side_effect(project_id: int):
            try:
                return projects[project_id]
            except KeyError:
                return {}

        def show_password_side_effect(password_id: int):
            try:
                return passwords[password_id]
            except KeyError:
                return {}

        self._tpm_api_mock.list_passwords_of_project.side_effect = (
            list_passwords_of_project_side_effect
        )
        self._tpm_api_mock.show_password.side_effect = show_password_side_effect

        result = self._team_password_manager.get_projects_passwords(project_ids)

        password_list = []

        for password in passwords.values():
            password_list.append(password)

        self.assertEqual(len(expected_passwords), len(result))

        for index, expected_password in enumerate(expected_passwords):
            self.assertEqual(expected_password.id, password_list[index]['id'])
            self.assertEqual(expected_password.name, password_list[index]['name'])
            self.assertEqual(expected_password.password, password_list[index]['password'])

    def test_get_certificate_by_project_id(self):
        def convert_certificate_to_tpm_data(id: int, name: str, data: dict) -> dict:
            certificate_string = data['certificate']
            key_string = data['key']

            return {
                'id': id,
                'name': name,
                'custom_field1': {'data': certificate_string},
                'custom_field2': {'data': certificate_string + certificate_string},
                'custom_field3': {'data': certificate_string
                                  + certificate_string
                                  + certificate_string
                                  },
                'custom_field4': {'data': key_string},
            }

        list_passwords_of_project_return_value = [
            {'id': 1, 'name': 'some_project_certificate_1'},
            {'id': 2, 'name': 'some_project_certificate_2'}
        ]

        id = 10
        name = 'foo'
        not_before = timedelta(days=1)
        not_after = timedelta(days=10)

        certificate_data = generate_certificate(not_before, not_after)
        tpm_response = convert_certificate_to_tpm_data(id, name, certificate_data)

        certificate_string = certificate_data['certificate']
        key_string = certificate_data['key']
        certificate_data = (
            x509.load_pem_x509_certificate(
                certificate_string.encode('ascii'),
                default_backend()
            )
        )

        expected_certificate = Certificate(
            id=id,
            cert=certificate_string,
            chain=certificate_string + certificate_string,
            full_chain=certificate_string + certificate_string + certificate_string,
            md5_cert=hashlib.md5(certificate_string.encode('utf-8')).hexdigest(),
            name=name,
            private_key=key_string,
            not_valid_after=certificate_data.not_valid_after,
            not_valid_before=certificate_data.not_valid_before,
        )

        self._tpm_api_mock.list_passwords_of_project.return_value = (
            list_passwords_of_project_return_value
        )
        self._tpm_api_mock.show_password.return_value = tpm_response

        certificate = self._team_password_manager.get_certificate_by_project_id(
            1,
            'some_project_certificate_1'
        )

        if certificate is None:
            self.fail("Failed to retreive certificate data")

        self.assertEqual(expected_certificate.id, certificate.id)
        self.assertEqual(expected_certificate.cert, certificate.cert)
        self.assertEqual(expected_certificate.chain, certificate.chain)
        self.assertEqual(expected_certificate.full_chain, certificate.full_chain)
        self.assertEqual(expected_certificate.md5_cert, certificate.md5_cert)
        self.assertEqual(expected_certificate.name, certificate.name)
        self.assertEqual(expected_certificate.private_key, certificate.private_key)
        self.assertEqual(expected_certificate.not_valid_after, certificate.not_valid_after)
        self.assertEqual(expected_certificate.not_valid_before, certificate.not_valid_before)

    def test_save_certificate(self):
        certificate = TpmCertificate(
            project_id=10,
            name="name",
            cert="cert",
            chain="chain",
            full_chain="full",
            private_key="pri"
        )

        expected_result = 10

        tpm_data = {
            'custom_data1': certificate.cert,
            'custom_data2': certificate.chain,
            'custom_data3': certificate.full_chain,
            'custom_data4': certificate.private_key,
            'name': certificate.name,
            'project_id': certificate.project_id,
        }

        self._tpm_api_mock.create_password.return_value = expected_result

        result = self._team_password_manager.save_certificate(certificate)

        self.assertEqual(expected_result, result)
        self._tpm_api_mock.create_password.assert_has_calls([call(data=tpm_data)], any_order=True)

    def test_update_certificate(self):
        certificate = TpmCertificate(
            project_id=10,
            name="name",
            cert="cert",
            chain="chain",
            full_chain="full",
            private_key="pri"
        )

        password_id = 20

        tpm_data = {
            'custom_data1': certificate.cert,
            'custom_data2': certificate.chain,
            'custom_data3': certificate.full_chain,
            'custom_data4': certificate.private_key,
            'name': certificate.name
        }

        self._tpm_api_mock.update_password.return_value = tpm_data

        self._team_password_manager.update_certificate(
            password_id=password_id,
            certificate=certificate
        )

        self.assertIsNotNone(certificate.project_id)
        self._tpm_api_mock.update_password.assert_has_calls(
            [call(ID=password_id,data=tpm_data)],
            any_order=True
        )

    def test_create_with_create_or_update_certificate(self):
        certificate = TpmCertificate(
            project_id=10,
            name="name",
            cert="cert",
            chain="chain",
            full_chain="full",
            private_key="pri"
        )

        tpm_data = {
            'custom_data1': certificate.cert,
            'custom_data2': certificate.chain,
            'custom_data3': certificate.full_chain,
            'custom_data4': certificate.private_key,
            'name': certificate.name,
            'project_id': certificate.project_id,
        }

        expected_result = 10

        self._tpm_api_mock.list_passwords_of_project.return_value = []
        self._tpm_api_mock.create_password.return_value = expected_result

        result = self._team_password_manager.save_or_update_certificate(certificate)

        self.assertEqual(expected_result, result)
        self._tpm_api_mock.create_password.assert_has_calls([call(data=tpm_data)], any_order=True)

    def test_update_with_create_or_update_certificate(self):
        certificate_data = generate_certificate(
            not_before=timedelta(),
            not_after=timedelta()
        )

        certificate_string = certificate_data['certificate']
        key_string = certificate_data['key']

        password_id = 123
        password_name = 'name'
        project_id = 10

        existing_certificate = {
            'id': password_id,
            'name': password_name,
            'custom_field1': {'data': certificate_string},
            'custom_field2': {'data': certificate_string},
            'custom_field3': {'data': certificate_string},
            'custom_field4': {'data': key_string},
        }

        updated_certificate_string = certificate_string + certificate_string

        certificate = TpmCertificate(
            project_id=project_id,
            name=password_name,
            cert=updated_certificate_string,
            chain=updated_certificate_string,
            full_chain=updated_certificate_string,
            private_key=key_string
        )

        updated_certificate = {
            'name': password_name,
            'custom_data1': updated_certificate_string,
            'custom_data2': updated_certificate_string,
            'custom_data3': updated_certificate_string,
            'custom_data4': key_string,
        }

        self._tpm_api_mock.list_passwords_of_project.return_value = [existing_certificate]
        self._tpm_api_mock.show_password.return_value = existing_certificate

        result = self._team_password_manager.save_or_update_certificate(certificate)

        self.assertEqual(password_id, result)
        self._tpm_api_mock.update_password.assert_has_calls(
            [call(ID=password_id, data=updated_certificate)],
            any_order=True
        )
        self.assertFalse(self._tpm_api_mock.create_password.called)


def cache_with_custom_ttl_data_provider():
    return (
        (
            100,
            100,
        ),
        (
            None,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
        ),
        (
            -100,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
        ),
        (
            0,
            0,
        ),
    )

encrypt_mock_side_effect = lambda x: x.decode()
decrypt_mock_side_effect = lambda x: x.encode()
ENCRYPTION_KEY = "9be220f0470b4da3729eadb79c641506ce1502c3428c5d996c8b7c3772af9387"

class TestCacheUpdate(unittest.TestCase):
    team_password_manager: Mock
    reids: Mock
    caching_team_password_manager: CachingTeamPasswordManager

    def setUp(self) -> None:
        self.team_password_manager = Mock()
        self.redis = Mock()
        self.caching_team_password_manager = CachingTeamPasswordManager(
            self.team_password_manager,
            self.redis,
            ENCRYPTION_KEY,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
            update_cache=True
        )

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.encrypt")
    def test_get_password(
        self,
        encrypt: Mock
    ):
        encrypt.side_effect = encrypt_mock_side_effect
        password_id = 10

        password = Password(1, 'name', 'password')
        password_json = json.dumps(password.__dict__)
        self.team_password_manager.get_password = Mock()
        self.team_password_manager.get_password.return_value = password
        self.redis.get = Mock()
        self.redis.setex = Mock()

        self.caching_team_password_manager.get_password(password_id)

        self.team_password_manager.get_password.assert_called_once_with(password_id)
        self.redis.get.assert_not_called()
        self.redis.setex.assert_called_once_with(
            generate_password_cache_key(password_id),
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
            password_json
        )
        encrypt.assert_called_once_with(password_json.encode())

class TestCachingTeamPasswordManager(unittest.TestCase):
    team_password_manager: Mock
    reids: Mock
    caching_team_password_manager: CachingTeamPasswordManager

    def setUp(self) -> None:
        self.team_password_manager = Mock()
        self.redis = Mock()
        self.caching_team_password_manager = CachingTeamPasswordManager(
            self.team_password_manager,
            self.redis,
            ENCRYPTION_KEY,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL
        )

    @data_provider(cache_with_custom_ttl_data_provider)
    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.encrypt")
    def test_cache_with_custom_ttl(
        self,
        custom_cache_ttl: Union[int, None],
        expected_cache_ttl: Union[int, None],
        encrypt: Mock
    ):
        password_id = 10
        encrypt.side_effect = encrypt_mock_side_effect

        password = Password(1, 'name', 'password')

        self.redis.setex = Mock()
        self.redis.get = Mock()
        self.redis.get.return_value = None
        self.team_password_manager.get_password = Mock()
        self.team_password_manager.get_password.return_value = password

        manager = CachingTeamPasswordManager(
            self.team_password_manager,
            self.redis,
            ENCRYPTION_KEY,
            custom_cache_ttl,
        )

        manager.get_password(password_id)

        password_json = json.dumps(password.__dict__)
        self.team_password_manager.get_password.assert_called_once_with(password_id)
        self.redis.setex.assert_called_once_with(
            generate_password_cache_key(password_id),
            expected_cache_ttl,
            password_json
        )
        encrypt.assert_called_once_with(password_json.encode())

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.decrypt")
    def test_cache_hit_on_get_password(
        self,
        decrypt: Mock,
    ):
        decrypt.side_effect = decrypt_mock_side_effect
        password_id = '10'
        password_name = 'password_name'
        password_value = 'password_value'

        cache_key = generate_password_cache_key(password_id)

        self.redis.get = Mock()
        self.redis.setex = Mock()
        self.team_password_manager.get_password = Mock()
        password_json = json.dumps({
            'id': password_id,
            'name': password_name,
            'password': password_value
        })
        self.redis.get.return_value = password_json
        result = self.caching_team_password_manager.get_password(password_id)

        self.assertIsInstance(result, Password)
        self.assertIsNotNone(result)

        if result is not None:
            self.assertEqual(password_id, result.id)
            self.assertEqual(password_name, result.name)
            self.assertEqual(password_value, result.password)
            self.redis.setex.assert_not_called()

        self.redis.get.assert_called_once_with(cache_key)
        decrypt.assert_called_once_with(password_json)
        self.redis.setex.assert_not_called()
        self.team_password_manager.get_password.assert_not_called()

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.encrypt")
    def test_cache_miss_on_get_password(self, encrypt: Mock):
        encrypt.side_effect = encrypt_mock_side_effect
        password_id = 10
        password_name = 'password_name'
        password_value = 'password_value'

        cache_key = generate_password_cache_key(password_id)

        self.redis.get = Mock()
        self.redis.setex = Mock()
        self.team_password_manager.get_password = Mock()

        password = Password(password_id, password_name, password_value)

        self.redis.get.return_value = None
        self.team_password_manager.get_password.return_value = password

        result = self.caching_team_password_manager.get_password(password_id)

        self.assertIsInstance(result, Password)
        self.assertIsNotNone(result)

        if result is not None:
            self.assertEqual(password.id, result.id)
            self.assertEqual(password.name, result.name)
            self.assertEqual(password.password, result.password)

        self.redis.get.assert_called_once_with(cache_key)
        self.redis.setex.assert_called_once_with(
            cache_key,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
            json.dumps(password.__dict__)
        )
        encrypt.assert_called_once_with(json.dumps(password.__dict__).encode())
        self.team_password_manager.get_password.assert_called_once_with(password_id)

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.decrypt")
    def test_cache_hit_on_get_passwords(self, decrypt: Mock):
        decrypt.side_effect = decrypt_mock_side_effect
        password_1_id = 10
        password_1_name = "password_name_1"
        password_1_value = "password_value_1"

        password_2_id = 11
        password_2_name = "password_name_2"
        password_2_value = "password_value_2"

        cache_key_1 = generate_password_cache_key(password_1_id)
        cache_key_2 = generate_password_cache_key(password_2_id)

        self.redis.get = Mock()
        self.redis.setex = Mock()
        self.team_password_manager.get_password = Mock()

        def redis_get_side_effect(cache_key: str) -> str:
            cache = {
                cache_key_1: {
                    "id": password_1_id,
                    "name": password_1_name,
                    "password": password_1_value
                },
                cache_key_2: {
                    "id": password_2_id,
                    "name": password_2_name,
                    "password": password_2_value
                },
            }

            return json.dumps(cache[cache_key])

        self.redis.get.side_effect = redis_get_side_effect

        passwords = self.caching_team_password_manager.get_passwords([password_1_id, password_2_id])

        expected_result = [
            Password(password_1_id, password_1_name, password_1_value),
            Password(password_2_id, password_2_name, password_2_value),
        ]

        self.assertEqual(len(expected_result), len(passwords))

        for idx, password in enumerate(passwords):
            self.assertEqual(password.id, expected_result[idx].id)
            self.assertEqual(password.name, expected_result[idx].name)
            self.assertEqual(password.password, expected_result[idx].password)

        self.redis.get.assert_has_calls(
            [call(cache_key_1), call(cache_key_2)],
            any_order=True
        )
        decrypt.assert_has_calls([
            call(json.dumps(expected_result[0].__dict__)),
            call(json.dumps(expected_result[1].__dict__)),
        ])
        self.redis.setex.assert_not_called()
        self.team_password_manager.get_password.assert_not_called()

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.encrypt")
    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.decrypt")
    def test_cache_miss_on_get_passwords(self, decrypt: Mock, encrypt: Mock):
        decrypt.side_effect = decrypt_mock_side_effect
        encrypt.side_effect = encrypt_mock_side_effect
        password_1 = {
            'id': 10,
            'name': 'password_name_1',
            'value': 'password_value_1'
        }

        password_2 = {
            'id': 11,
            'name': 'password_name_2',
            'value': 'password_value_2'
        }

        cache_key_1 = generate_password_cache_key(password_1['id'])
        cache_key_2 = generate_password_cache_key(password_2['id'])

        self.redis.get = Mock()
        self.redis.setex = Mock()
        self.team_password_manager.get_password = Mock()

        def redis_get_side_effect(cache_key: str) -> Union[str, None]:
            cache = {
                cache_key_1: {
                    'id': password_1['id'],
                    'name': password_1['name'],
                    'password': password_1['value']
                },
                cache_key_2: None
            }

            cache_item = cache[cache_key]

            if cache_item is None:
                return None

            return json.dumps(cache_item)

        expected_password_1 = Password(password_1['id'], password_1['name'], password_1['value'])
        expected_password_2 = Password(password_2['id'], password_2['name'], password_2['value'])

        self.redis.get.side_effect = redis_get_side_effect
        self.team_password_manager.get_password.return_value = expected_password_2

        passwords = self.caching_team_password_manager.get_passwords([
            password_1['id'],
            password_1['id'],
            password_2['id'],
        ])

        expected_result = [
            expected_password_1,
            expected_password_2,
        ]

        self.assertEqual(len(expected_result), len(passwords))

        for idx, password in enumerate(passwords):
            self.assertEqual(password.id, expected_result[idx].id)
            self.assertEqual(password.name, expected_result[idx].name)
            self.assertEqual(password.password, expected_result[idx].password)

        self.redis.get.assert_has_calls([call(cache_key_1), call(cache_key_2)], any_order=True)
        self.redis.setex.assert_called_once_with(
            cache_key_2,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
            json.dumps(expected_password_2.__dict__)
        )
        decrypt.assert_has_calls([call(json.dumps(expected_password_1.__dict__))], any_order=True)
        encrypt.assert_called_once_with(json.dumps(expected_password_2.__dict__).encode())
        self.team_password_manager.get_password.assert_called_once_with(password_2['id'])

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.decrypt")
    def test_cache_hit_on_get_certificate_by_project_id(self, decrypt: Mock):
        decrypt.side_effect = decrypt_mock_side_effect
        project_id = '10'
        password_name = 'password_name'
        date = datetime.now()
        cert_data = {
            'id': 10,
            'cert': 'cert',
            'chain': 'chain',
            'full_chain': 'full_chain',
            'md5_cert': 'md5_cert',
            'name': 'name',
            'private_key': 'private_key',
            'not_valid_after': date,
            'not_valid_before': date,
        }
        certificate_in_cache = Certificate(**cert_data)
        certificate_in_cache_json = json.dumps(
            certificate_in_cache.__dict__,
            default=str
        )

        self.redis.get = Mock()
        self.redis.setex = Mock()

        cache_key = generate_certificate_cache_key(project_id, password_name)

        self.redis.get.return_value = certificate_in_cache_json
        result = (
            self.caching_team_password_manager.get_certificate_by_project_id(
                project_id,
                password_name
            )
        )

        self.assertIsInstance(result, Certificate)
        self.assertIsNotNone(result)

        if result is not None:
            self.assertEqual(certificate_in_cache.id, result.id)
            self.assertEqual(certificate_in_cache.cert, result.cert)
            self.assertEqual(certificate_in_cache.chain, result.chain)
            self.assertEqual(certificate_in_cache.full_chain, result.full_chain)
            self.assertEqual(certificate_in_cache.md5_cert, result.md5_cert)
            self.assertEqual(certificate_in_cache.name, result.name)
            self.assertEqual(certificate_in_cache.private_key, result.private_key)
            self.assertEqual(certificate_in_cache.not_valid_after, result.not_valid_after)
            self.assertEqual(certificate_in_cache.not_valid_before, result.not_valid_before)

        self.redis.get.assert_called_once_with(cache_key)
        decrypt.assert_called_once_with(certificate_in_cache_json)
        self.redis.setex.assert_not_called()
        self.team_password_manager.get_certificate_by_project_id.assert_not_called()


    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.encrypt")
    def test_cache_miss_on_get_certificate_by_project_id(self, encrypt: Mock):
        encrypt.side_effect = encrypt_mock_side_effect
        project_id = 10
        password_name = 'password_name'
        date = datetime.now()
        cert_data = {
            'id': 10,
            'cert': 'cert',
            'chain': 'chain',
            'full_chain': 'full_chain',
            'md5_cert': 'md5_cert',
            'name': 'name',
            'private_key': 'private_key',
            'not_valid_after': date,
            'not_valid_before': date,
        }
        certificate_from_remote = Certificate(**cert_data)
        certificate_from_remote_json = json.dumps(certificate_from_remote.__dict__, default=str)

        self.redis.get = Mock()
        self.redis.setex = Mock()
        self.team_password_manager.get_certificate_by_project_id = Mock()
        self.team_password_manager.get_certificate_by_project_id.return_value = (
            certificate_from_remote
        )
        self.redis.get.return_value = None

        cache_key = generate_certificate_cache_key(project_id, password_name)
        result = (
            self.caching_team_password_manager.get_certificate_by_project_id(
                project_id,
                password_name
            )
        )

        self.assertIsInstance(result, Certificate)
        self.assertIsNotNone(result)

        if result is not None:
            self.assertEqual(certificate_from_remote.id, result.id)
            self.assertEqual(certificate_from_remote.cert, result.cert)
            self.assertEqual(certificate_from_remote.chain, result.chain)
            self.assertEqual(certificate_from_remote.full_chain, result.full_chain)
            self.assertEqual(certificate_from_remote.md5_cert, result.md5_cert)
            self.assertEqual(certificate_from_remote.name, result.name)
            self.assertEqual(certificate_from_remote.private_key, result.private_key)
            self.assertEqual(certificate_from_remote.not_valid_after, result.not_valid_after)
            self.assertEqual(certificate_from_remote.not_valid_before, result.not_valid_before)

        self.redis.get.assert_called_once_with(cache_key)
        self.redis.setex.assert_called_once_with(
            cache_key,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
            certificate_from_remote_json
        )
        encrypt.assert_called_once_with(certificate_from_remote_json.encode())
        self.team_password_manager.get_certificate_by_project_id.assert_called_once_with(
            project_id,
            password_name
        )

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.decrypt")
    def test_cache_hit_get_projects_passwords(
        self,
        decrypt: Mock
    ):
        decrypt.side_effect = decrypt_mock_side_effect

        project_ids = ["1", 2, 3]
        passwords = [
            Password(1, "one", "one"),
            Password(2, "two", "two"),
            Password(3, "three", "three"),
        ]

        self.redis.get = Mock()

        def redis_get_side_effect(cache_key: str) -> str:
            cache = {
                generate_get_projects_password_ids_cache_key("1"): json.dumps([3]),
                generate_get_projects_password_ids_cache_key(2): json.dumps([4]),
                generate_get_projects_password_ids_cache_key(3): json.dumps([5]),

                generate_password_cache_key(3): json.dumps(passwords[0].__dict__),
                generate_password_cache_key(4): json.dumps(passwords[1].__dict__),
                generate_password_cache_key(5): json.dumps(passwords[2].__dict__),
            }

            return cache[cache_key]
        self.redis.get.side_effect = redis_get_side_effect

        result = self.caching_team_password_manager.get_projects_passwords(project_ids)

        self.assertEqual(len(result), len(passwords))

        for idx, password in enumerate(result):
            self.assertEqual(password.id, passwords[idx].id)
            self.assertEqual(password.name, passwords[idx].name)
            self.assertEqual(password.password, passwords[idx].password)

        self.redis.get.assert_has_calls([
            call(generate_get_projects_password_ids_cache_key("1")),
            call(generate_password_cache_key(3)),
            call(generate_get_projects_password_ids_cache_key(2)),
            call(generate_password_cache_key(4)),
            call(generate_get_projects_password_ids_cache_key(3)),
            call(generate_password_cache_key(5)),
        ])

        decrypt.assert_has_calls([
            call(json.dumps([3])),
            call(json.dumps(passwords[0].__dict__)),
            call(json.dumps([4])),
            call(json.dumps(passwords[1].__dict__)),
            call(json.dumps([5])),
            call(json.dumps(passwords[2].__dict__)),
        ])

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.encrypt")
    def test_cache_miss_get_projects_passwords(
        self,
        encrypt: Mock
    ):
        encrypt.side_effect = encrypt_mock_side_effect
        project_ids = [1, 2]
        passwords = [
            Password(1, "one", "one"),
            Password(2, "two", "two"),
        ]

        self.redis.get = Mock()
        self.redis.get.return_value = None
        self.redis.setex = Mock()

        def get_projects_password_ids_side_effect(password_id: int) -> List[int]:
            data = {
                1: [3],
                2: [4],
            }

            return data[password_id]
        self.team_password_manager.get_projects_password_ids = Mock()
        self.team_password_manager.get_projects_password_ids.side_effect = (
            get_projects_password_ids_side_effect
        )
        def get_password_side_effect(password_id: int) -> Password:
            data = {
                3: passwords[0],
                4: passwords[1],
            }

            return data[password_id]
        self.team_password_manager.get_password = Mock()
        self.team_password_manager.get_password.side_effect = (
            get_password_side_effect
        )

        result = self.caching_team_password_manager.get_projects_passwords(project_ids)

        self.assertEqual(len(result), len(passwords))

        for idx, password in enumerate(result):
            self.assertEqual(password.id, passwords[idx].id)
            self.assertEqual(password.name, passwords[idx].name)
            self.assertEqual(password.password, passwords[idx].password)

        self.redis.get.assert_has_calls([
            call(generate_get_projects_password_ids_cache_key(1)),
            call(generate_password_cache_key(3)),
            call(generate_get_projects_password_ids_cache_key(2)),
            call(generate_password_cache_key(4)),
        ])

        self.redis.setex.assert_has_calls([
            call(
                generate_get_projects_password_ids_cache_key(1),
                CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
                json.dumps([3]),
            ),
            call(
                generate_password_cache_key(3),
                CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
                json.dumps(passwords[0].__dict__),
            ),
            call(
                generate_get_projects_password_ids_cache_key(2),
                CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
                json.dumps([4]),
            ),
            call(
                generate_password_cache_key(4),
                CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
                json.dumps(passwords[1].__dict__),
            ),
        ])

        encrypt.assert_has_calls([
            call(json.dumps([3]).encode()),
            call(json.dumps(passwords[0].__dict__).encode()),
            call(json.dumps([4]).encode()),
            call(json.dumps(passwords[1].__dict__).encode()),
        ])

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.decrypt")
    def test_cache_hit_get_certificate(
        self,
        decrypt: Mock,
    ):
        decrypt.side_effect = decrypt_mock_side_effect
        password_id = 10
        cache_key = generate_get_certificate(password_id)
        certificate = create_certificate()
        certificate_json = json.dumps(certificate.__dict__, default=str)


        self.redis.get = Mock()
        self.redis.get.return_value = certificate_json
        self.team_password_manager.get_password = Mock()

        result = self.caching_team_password_manager.get_certificate(password_id)

        self.assertEqual(certificate.id, result.id)

        self.redis.get.assert_called_once_with(cache_key)
        self.team_password_manager.get_password.assert_not_called()
        decrypt.assert_called_once_with(certificate_json)

    @patch("ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager.nacl.secret.SecretBox.encrypt")
    def test_cache_miss_get_certificate(
        self,
        encrypt: Mock
    ):
        encrypt.side_effect = encrypt_mock_side_effect

        password_id = 10
        cache_key = generate_get_certificate(password_id)
        certificate = create_certificate()
        certificate_json = json.dumps(certificate.__dict__, default=str)

        self.redis.get = Mock()
        self.redis.get.return_value = None
        self.team_password_manager.get_certificate = Mock()
        self.team_password_manager.get_certificate.return_value = certificate

        result = self.caching_team_password_manager.get_certificate(password_id)

        self.assertEqual(certificate.id, result.id)

        self.redis.get.assert_called_once_with(cache_key)
        self.redis.setex.assert_called_once_with(
            cache_key,
            CachingTeamPasswordManager.DEFAULT_CACHE_TTL,
            certificate_json
        )
        self.team_password_manager.get_certificate.assert_called_once_with(password_id)
        encrypt.assert_called_once_with(certificate_json.encode())

    def test_save_or_update_certificate(self):
        tpm_certificate = Mock()

        self.team_password_manager.save_or_update_certificate = Mock()
        self.team_password_manager.save_or_update_certificate.return_value = 10

        result = self.caching_team_password_manager.save_or_update_certificate(tpm_certificate)

        self.assertEqual(10, result)
        self.team_password_manager.save_or_update_certificate.assert_called_once_with(tpm_certificate)


def create_certificate():
    return Certificate(
        "id",
        "cert",
        "chain",
        "full_chain",
        "md5_cert",
        "name",
        "private_key",
        datetime.now(),
        datetime.now(),
    )
