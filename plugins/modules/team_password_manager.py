#!/usr/bin/python

from typing import List
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.nordsec.team_password_manager.plugins.module_utils.factory import (
    TeamPasswordManagerFactory,
)
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.entities import (
    Password,
    TpmCertificate,
    Certificate
)

DOCUMENTATION = '''
    - name: Team password manager example
        nordsec.team_password_manager.team_password_manager:
            auth: "auth:deploy"
            update_cache: True
            get_password: 2219
            get_passwords: [2268, 2406]
            get_passwords_from_project: 327
            get_passwords_from_projects: [332, 333]
            get_cert_from_project:
                pid: 123
                name: "my.domain.name"
            put_cert_to_project:
                pid: "123"
                name: "{{ domainname }}"
                cert: "{{ cert_file.stdout }}"
                chain: "{{ chain_file.stdout }}"
                fullchain: "{{ fullchain_file.stdout }}"
                privkey: "{{ privkey_file.stdout }}"
        register: result

    - name: debug
        debug:
            msg: "{{ result }}"
'''

ACTION_GET_PASSWORD = 'get_password'
ACTION_GET_PASSWORDS = 'get_passwords'
ACTION_GET_PASSWORDS_FROM_PROJECT = 'get_passwords_from_project'
ACTION_GET_PASSWORDS_FROM_PROJECTS = 'get_passwords_from_projects'
ACTION_GET_CERT_FROM_PROJECT = 'get_cert_from_project'
ACTION_PUT_CERT_TO_PROJECT = 'put_cert_to_project'

ACTION_TYPES = {
    ACTION_GET_PASSWORD: ACTION_GET_PASSWORD,
    ACTION_GET_PASSWORDS: ACTION_GET_PASSWORDS,
    ACTION_GET_PASSWORDS_FROM_PROJECT: ACTION_GET_PASSWORDS_FROM_PROJECT,
    ACTION_GET_PASSWORDS_FROM_PROJECTS: ACTION_GET_PASSWORDS_FROM_PROJECTS,
    ACTION_GET_CERT_FROM_PROJECT: ACTION_GET_CERT_FROM_PROJECT,
    ACTION_PUT_CERT_TO_PROJECT: ACTION_PUT_CERT_TO_PROJECT
}


def create_tpm_certificate(param_data: dict) -> TpmCertificate:
    return TpmCertificate(
        name=param_data['name'],
        cert=param_data['cert'],
        chain=param_data['chain'],
        full_chain=param_data['fullchain'],
        private_key=param_data['privkey'],
        project_id=param_data['pid']
    )


def create_certificate_result(certificate: Certificate) -> dict:
    return {
        'cert': certificate.cert,
        'chain': certificate.chain,
        'fullchain': certificate.full_chain,
        'md5_cert': certificate.md5_cert,
        'not_valid_after': str(certificate.not_valid_after),
        'not_valid_before': str(certificate.not_valid_before),
        'privkey': certificate.private_key,
    }


def create_updated_certificate_result(password_id: int, password_name: str) -> dict:
    return {'id': password_id, 'name': password_name}


def create_passwords_result(passwords: List[Password]) -> dict:
    result = {}

    for password in passwords:
        result.update({password.name: password.password})

    return result


def is_action(action: str, parameters: dict) -> bool:
    return action in parameters and parameters[action] is not None


def return_module_result(module: AnsibleModule, result: dict):
    module.exit_json(**{
        "tpm": result,
        "changed": False,
    })


def main():
    module_args = dict(
        auth=dict(type=str, required=True),
        update_cache=dict(type=bool, required=False),
        get_password=dict(type=int, required=False),
        get_passwords=dict(type=list, required=False),
        get_passwords_from_project=dict(type=int, required=False),
        get_passwords_from_projects=dict(type=list, required=False),
        get_cert_from_project=dict(type=dict, required=False),
        put_cert_to_project=dict(type=dict, required=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    result = {}

    password_manager = (TeamPasswordManagerFactory()).create(
        module.params['auth'],
        module.params['update_cache'],
    )

    if is_action(ACTION_PUT_CERT_TO_PROJECT, module.params):
        certificate = create_tpm_certificate(module.params[ACTION_PUT_CERT_TO_PROJECT])
        password_id = password_manager.save_or_update_certificate(certificate)
        result = create_updated_certificate_result(password_id, certificate.name)

        return_module_result(module, result)

    result = {}

    if is_action(ACTION_GET_CERT_FROM_PROJECT, module.params):
        certificate = password_manager.get_certificate_by_project_id(
            module.params[ACTION_GET_CERT_FROM_PROJECT]['pid'],
            module.params[ACTION_GET_CERT_FROM_PROJECT]['name']
        )

        if certificate is not None:
            result.update(create_certificate_result(certificate))

    if is_action(ACTION_GET_PASSWORD, module.params):
        password_id = module.params[ACTION_GET_PASSWORD]
        passwords = password_manager.get_passwords([password_id])
        result.update(create_passwords_result(passwords))

    if is_action(ACTION_GET_PASSWORDS, module.params):
        password_ids = module.params[ACTION_GET_PASSWORDS]
        passwords = password_manager.get_passwords(password_ids)
        result.update(create_passwords_result(passwords))

    if is_action(ACTION_GET_PASSWORDS_FROM_PROJECT, module.params):
        project_id = module.params[ACTION_GET_PASSWORDS_FROM_PROJECT]
        passwords = password_manager.get_projects_passwords([project_id])
        result.update(create_passwords_result(passwords))

    if is_action(ACTION_GET_PASSWORDS_FROM_PROJECTS, module.params):
        project_ids = module.params[ACTION_GET_PASSWORDS_FROM_PROJECTS]
        passwords = password_manager.get_projects_passwords(project_ids)
        result.update(create_passwords_result(passwords))

    return_module_result(module, result)

    module.fail_json('Unsupported action parameter selected')


if __name__ == "__main__":
    main()
