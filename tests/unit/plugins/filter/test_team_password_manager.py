# pylint: disable=C0301

from datetime import datetime
import unittest
from mock import Mock, patch

from ansible_collections.nordsec.team_password_manager.plugins.filter.team_password_manager import FilterModule
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.entities import Password, Certificate

def test_filter_mapping():
    module = FilterModule()

    expected_filters = {
        'get_password': module.get_password,
        'get_cert': module.get_certificate,
    }

    assert expected_filters == module.filters()


class TestFilterModule(unittest.TestCase):

    @patch('ansible_collections.nordsec.team_password_manager.plugins.module_utils.factory.TeamPasswordManagerFactory.create')
    def test_get_password(
        self,
        tpm_factory_create: Mock,
    ):
        team_password_manager = Mock()
        tpm_factory_create.return_value = team_password_manager

        module = FilterModule()

        test_data = {
            "input": {
                "auth": "foo",
                "id": 123
            },
            "password": {
                "id": 1,
                "name": "pass_name",
                "value": "pass_value",
            }
        }

        password = Password(
            test_data["password"]["id"],
            test_data["password"]["value"],
            test_data["password"]["value"],
        )

        team_password_manager.get_passwords = Mock()
        team_password_manager.get_passwords.return_value = [password]

        password = module.get_password(test_data["input"])

        assert test_data["password"]["value"] == password

        team_password_manager.get_passwords.assert_called_once_with([test_data["input"]["id"]])
        tpm_factory_create.assert_called_once_with(test_data["input"]["auth"])

    @patch('ansible_collections.nordsec.team_password_manager.plugins.module_utils.factory.TeamPasswordManagerFactory.create')
    def test_get_certificate(
        self,
        tpm_factory_create: Mock,
    ):

        test_data = {
            "certificate": {
                'id': 123,
                'cert': 'cet',
                'chain': 'chain',
                'full_chain': 'full_cain',
                'md5_cert': 'md5_cert',
                'name': 'name',
                'private_key': 'priv_key',
                'not_valid_after': datetime.now(),
                'not_valid_before': datetime.now(),
            },
            "input": {
                "auth": "foo",
                "id": 123
            }
        }

        expected_result = {
            'cert': test_data['certificate']['cert'],
            'chain': test_data['certificate']['chain'],
            'fullchain': test_data['certificate']['full_chain'],
            'privkey': test_data['certificate']['private_key'],
        }

        certificate = Certificate(
            test_data['certificate']['id'],
            test_data['certificate']['cert'],
            test_data['certificate']['chain'],
            test_data['certificate']['full_chain'],
            test_data['certificate']['md5_cert'],
            test_data['certificate']['name'],
            test_data['certificate']['private_key'],
            test_data['certificate']['not_valid_after'],
            test_data['certificate']['not_valid_before'],
        )

        team_password_manager = Mock()
        tpm_factory_create.return_value = team_password_manager
        module = FilterModule()

        team_password_manager.get_certificate = Mock()
        team_password_manager.get_certificate.return_value = certificate

        result = module.get_certificate(test_data["input"])

        assert result == expected_result

        team_password_manager.get_certificate.assert_called_once_with(test_data["input"]["id"])
        tpm_factory_create.assert_called_once_with(test_data["input"]["auth"])
