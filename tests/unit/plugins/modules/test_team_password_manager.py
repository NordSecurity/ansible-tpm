# pylint: disable=C0301

from datetime import datetime
from typing import List
from unittest import mock
import unittest
import json
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes
import redis
from ansible_collections.nordsec.team_password_manager.plugins.modules import team_password_manager


def set_module_args(args):
    args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
    basic._ANSIBLE_ARGS = to_bytes(args)  # pylint: disable=W0212


def fail_json(*args, **kwargs):  # pylint: disable=W0613
    kwargs['failed'] = True
    raise AnsibleFailJson(kwargs)


def exit_json(*args, **kwargs):  # pylint: disable=W0613
    if 'changed' not in kwargs:
        kwargs['changed'] = False
    raise AnsibleExitJson(kwargs)


class AnsibleFailJson(Exception):
    pass


class AnsibleExitJson(Exception):
    pass


class TestTpmModule(unittest.TestCase):
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.fail_json')
    def test_module_fail_when_required_args_missing(self, ansible_module_mock):
        ansible_module_mock.side_effect = fail_json

        with self.assertRaises(AnsibleFailJson):
            set_module_args({})
            team_password_manager.main()

    def redis_ping_side_effect(self, *args):
        raise redis.exceptions.ConnectionError()

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.TeamPasswordManagerFactory.create')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.exit_json')
    def test_get_passwords(
        self,
        exit_json_mock: mock.Mock,
        tpm_factory_create: mock.Mock,
    ):
        exit_json_mock.side_effect = exit_json

        auth = 'some:auth'
        password_ids = [1,2]

        set_module_args({
            'auth': auth,
            'get_passwords': password_ids,
        })

        manager = mock.Mock()
        tpm_factory_create.return_value = manager

        password1 = team_password_manager.Password(1, 'password_name_1', 'password_value_1')
        password2 = team_password_manager.Password(2, 'password_name_2', 'password_value_2')

        manager.get_passwords.return_value = [password1, password2]

        with self.assertRaises(AnsibleExitJson) as result:
            team_password_manager.main()

        expected_exit_json = {
            'tpm': {
                password1.name: password1.password,
                password2.name: password2.password,
            },
            'changed': False
        }

        manager.get_passwords.assert_called_once_with(password_ids)
        self.assertEqual(expected_exit_json, result.exception.args[0])

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.TeamPasswordManagerFactory.create')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.exit_json')
    def test_get_passwords_by_ids_and_projects(
        self,
        exit_json_mock: mock.Mock,
        tpm_factory_create: mock.Mock,
    ):
        exit_json_mock.side_effect = exit_json

        set_module_args({
            'auth': 'some:auth',
            team_password_manager.ACTION_GET_PASSWORD: 0,
            team_password_manager.ACTION_GET_PASSWORDS: [1, 2],
            team_password_manager.ACTION_GET_PASSWORDS_FROM_PROJECT: 10,
            team_password_manager.ACTION_GET_PASSWORDS_FROM_PROJECTS: [11, 12],
        })

        manager = mock.Mock()
        tpm_factory_create.return_value = manager

        passwords = []
        for seq in range(6):
            name = 'password_name_%d' % (seq)
            value = 'password_value_%d' % (seq)
            passwords.append(team_password_manager.Password(seq, name, value))

        def get_passwords_side_effect(password_ids: List[int]):
            if password_ids == [0]:
                return [passwords[0]]

            if password_ids == [1, 2]:
                return [passwords[1], passwords[2]]

            return []

        def get_projects_passwords(project_ids: List[int]):
            if project_ids == [10]:
                return [passwords[3]]

            if project_ids == [11, 12]:
                return [passwords[4], passwords[5]]

            return []

        manager.get_passwords.side_effect = get_passwords_side_effect
        manager.get_projects_passwords.side_effect = get_projects_passwords

        with self.assertRaises(AnsibleExitJson) as result:
            team_password_manager.main()

        expected_exit_json = {
            'tpm': {
                passwords[0].name: passwords[0].password,
                passwords[1].name: passwords[1].password,
                passwords[2].name: passwords[2].password,
                passwords[3].name: passwords[3].password,
                passwords[4].name: passwords[4].password,
                passwords[5].name: passwords[5].password
            },
            'changed': False
        }

        manager.get_passwords.assert_has_calls([
            mock.call([0]),
            mock.call([1, 2]),
        ])
        manager.get_projects_passwords.assert_has_calls([
            mock.call([10]),
            mock.call([11, 12]),
        ])
        self.assertEqual(expected_exit_json, result.exception.args[0])

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.TeamPasswordManagerFactory.create')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.exit_json')
    def test_get_password(
        self,
        exit_json_mock: mock.Mock,
        tpm_factory_create: mock.Mock,
    ):
        exit_json_mock.side_effect = exit_json

        auth = 'some:auth'
        password_id = 1

        set_module_args({
            'auth': auth,
            'get_password': password_id,
        })

        manager = mock.Mock()
        tpm_factory_create.return_value = manager

        password = team_password_manager.Password(1, 'password_name_1', 'password_value_1')

        manager.get_passwords.return_value = [password]
        with self.assertRaises(AnsibleExitJson) as result:
            team_password_manager.main()

        expected_exit_json = {
            'tpm': {
                password.name: password.password,
            },
            'changed': False
        }

        manager.get_passwords.assert_called_once_with([password_id])
        self.assertEqual(expected_exit_json, result.exception.args[0])

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.TeamPasswordManagerFactory.create')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.exit_json')
    def test_get_project_passwords(
        self,
        exit_json_mock: mock.Mock,
        tpm_factory_create: mock.Mock,
    ):
        exit_json_mock.side_effect = exit_json

        auth = 'some:auth'
        project_id = 1

        set_module_args({
            'auth': auth,
            'get_passwords_from_project': project_id,
        })

        manager = mock.Mock()
        tpm_factory_create.return_value = manager

        password = team_password_manager.Password(1, 'password_name_1', 'password_value_1')

        manager.get_projects_passwords.return_value = [password]

        with self.assertRaises(AnsibleExitJson) as result:
            team_password_manager.main()

        expected_exit_json = {
            'tpm': {
                password.name: password.password,
            },
            'changed': False
        }

        manager.get_projects_passwords.assert_called_once_with([project_id])
        self.assertEqual(expected_exit_json, result.exception.args[0])

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.TeamPasswordManagerFactory.create')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.exit_json')
    def test_get_passwords_from_projects(
        self,
        exit_json_mock: mock.Mock,
        tpm_factory_create: mock.Mock,
    ):
        exit_json_mock.side_effect = exit_json

        auth = 'some:auth'
        project_ids = [1,2]

        set_module_args({
            'auth': auth,
            'get_passwords_from_projects': [1,2],
        })

        manager = mock.Mock()
        tpm_factory_create.return_value = manager

        password1 = team_password_manager.Password(1, 'password_name_1', 'password_value_1')
        password2 = team_password_manager.Password(2, 'password_name_2', 'password_value_2')

        manager.get_projects_passwords.return_value = [password1, password2]

        with self.assertRaises(AnsibleExitJson) as result:
            team_password_manager.main()

        expected_exit_json = {
            'tpm': {
                password1.name: password1.password,
                password2.name: password2.password,
            },
            'changed': False
        }

        manager.get_projects_passwords.assert_called_once_with(project_ids)
        self.assertEqual(expected_exit_json, result.exception.args[0])

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.TeamPasswordManagerFactory.create')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.exit_json')
    def test_get_cert_from_project(
        self,
        exit_json_mock: mock.Mock,
        api_factory_create: mock.Mock,
    ):
        exit_json_mock.side_effect = exit_json

        auth = 'some:auth'
        project_id = 'project_id'
        password_name = 'password_name'

        set_module_args({
            'auth': auth,
            'get_cert_from_project': {
                'pid': project_id,
                'name': password_name,
            }
        })

        manager = mock.Mock()
        api_factory_create.return_value = manager

        certificate = team_password_manager.Certificate(
            id=10,
            cert='cert',
            chain='chain',
            full_chain='full_chain',
            md5_cert='md5_cert',
            name='name',
            private_key='private_key',
            not_valid_after=datetime.now(),
            not_valid_before=datetime.now()
        )

        manager.get_certificate_by_project_id.return_value = certificate

        with self.assertRaises(AnsibleExitJson) as result:
            team_password_manager.main()

        expected_exit_json = {
            'tpm': {
                'md5_cert': certificate.md5_cert,
                'cert': certificate.cert,
                'chain': certificate.chain,
                'fullchain': certificate.full_chain,
                'privkey': certificate.private_key,
                'not_valid_before': str(certificate.not_valid_before),
                'not_valid_after': str(certificate.not_valid_after),
            },
            'changed': False
        }

        manager.get_certificate_by_project_id.assert_called_once_with(
            project_id,
            password_name
        )
        self.assertEqual(expected_exit_json, result.exception.args[0])

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.create_tpm_certificate')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.TeamPasswordManagerFactory.create')
    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.exit_json')
    def test_put_cert_from_project(
        self,
        exit_json_mock: mock.Mock,
        api_factory_create: mock.Mock,
        create_tpm_certificate: mock.Mock,
    ):
        exit_json_mock.side_effect = exit_json

        module_args = {
            'auth':'some:auth',
            'project_id':1,
            'password_name':'password_name',
            'cert':'cert',
            'chain':'chain',
            'full_chain':'full_chain',
            'private_key':'private_key',
        }

        set_module_args({
            'auth': module_args['auth'],
            'put_cert_to_project': {
                'pid': module_args['project_id'],
                'name': module_args['password_name'],
                'cert': module_args['cert'],
                'chain': module_args['chain'],
                'fullchain': module_args['full_chain'],
                'privkey': module_args['private_key'],
            }
        })

        certificate = team_password_manager.TpmCertificate(
            name=module_args['password_name'],
            cert=module_args['cert'],
            chain=module_args['chain'],
            full_chain=module_args['full_chain'],
            private_key=module_args['private_key'],
            project_id=module_args['project_id']
        )

        create_tpm_certificate.return_value = certificate

        manager = mock.Mock()
        api_factory_create.return_value = manager

        manager.save_or_update_certificate.return_value = module_args['project_id']

        with self.assertRaises(AnsibleExitJson) as result:
            team_password_manager.main()

        expected_exit_json = {
            'tpm': {
                'id': module_args['project_id'],
                'name': module_args['password_name'],
            },
            'changed': False
        }

        manager.save_or_update_certificate.assert_called()
        self.assertEqual(expected_exit_json, result.exception.args[0])

    def test_create_tpm_certificate(self):
        project_id = 1
        password_name = 'password_name'
        cert = 'cert'
        chain = 'chain'
        full_chain = 'full_chain'
        private_key = 'private_key'

        params = {
            'pid': project_id,
            'name': password_name,
            'cert': cert,
            'chain': chain,
            'fullchain': full_chain,
            'privkey': private_key,
        }

        certificate = team_password_manager.create_tpm_certificate(param_data=params)

        self.assertEqual(project_id, certificate.project_id)
        self.assertEqual(password_name, certificate.name)
        self.assertEqual(cert, certificate.cert)
        self.assertEqual(chain, certificate.chain)
        self.assertEqual(full_chain, certificate.full_chain)
        self.assertEqual(private_key, certificate.private_key)

    @mock.patch('ansible_collections.nordsec.team_password_manager.plugins.modules.team_password_manager.AnsibleModule.fail_json')
    def test_with_random_action(self, ansible_module_mock):
        ansible_module_mock.side_effect = fail_json

        with self.assertRaises(AnsibleFailJson):
            set_module_args({'auth': 'auth', 'hello': 'world'})
            team_password_manager.main()
