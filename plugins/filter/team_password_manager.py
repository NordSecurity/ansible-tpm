from ansible_collections.nordsec.team_password_manager.plugins.module_utils.factory import (
    TeamPasswordManagerFactory
)
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.entities import (
    Certificate
)


class FilterModule():
    def filters(self):
        return {
            'get_password': self.get_password,
            'get_cert': self.get_certificate,
        }

    def get_password(self, params) -> str:
        password_manager = (TeamPasswordManagerFactory()).create(params['auth'])

        return password_manager.get_passwords([params['id']])[0].password

    def get_certificate(self, params) -> Certificate:
        password_manager = (TeamPasswordManagerFactory()).create(params['auth'])

        certificate = password_manager.get_certificate(params['id'])

        return {
            'cert': certificate.cert,
            'chain': certificate.chain,
            'fullchain': certificate.full_chain,
            'privkey': certificate.private_key,
        }
