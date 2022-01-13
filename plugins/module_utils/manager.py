from datetime import datetime, timedelta
import json
from abc import ABC, abstractmethod
from typing import List, Union, Any
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import redis
import tpm
import nacl.secret
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.entities import (
    Certificate,
    Password,
    ProjectPassword,
    TpmCertificate,
)

_CacheValue = str

class BaseTeamPasswordManager(ABC):
    @abstractmethod
    def save_or_update_certificate(self, tpm_certificate: TpmCertificate) -> int:
        pass

    @abstractmethod
    def get_certificate_by_project_id(
        self,
        project_id: int,
        name: str
    ) -> Union[Certificate, None]:
        pass

    @abstractmethod
    def get_passwords(self, password_ids: List[int]) -> List[Password]:
        pass

    @abstractmethod
    def get_projects_passwords(self, project_ids: List[int]) -> List[Password]:
        pass


class BaseTeamPasswordManager(ABC):
    @abstractmethod
    def save_or_update_certificate(self, tpm_certificate: TpmCertificate) -> int:
        pass

    @abstractmethod
    def get_certificate_by_project_id(
        self,
        project_id: int,
        name: str
    ) -> Union[Certificate, None]:
        pass

    @abstractmethod
    def get_passwords(self, password_ids: List[int]) -> List[Password]:
        pass

    @abstractmethod
    def get_projects_passwords(self, project_ids: List[int]) -> List[Password]:
        pass


def generate_password_cache_key(password_id: int) -> str:
    return 'tpm.get_password.%d' % (int(password_id))


def generate_certificate_cache_key(project_id: int, password_name: str) -> str:
    return 'tpm.get_certificate_by_project_id.%d.%s' % (int(project_id), password_name)


def generate_get_certificate(password_id: int) -> str:
    return 'tpm.get_certificate.%d' % (int(password_id))


def generate_get_projects_password_ids_cache_key(project_id: int) -> str:
    return 'tpm.get_projects_password_ids.%d' % (int(project_id))


class TeamPasswordManager(BaseTeamPasswordManager):
    _connection: tpm.TpmApiv4

    def __init__(self, tpm_api: tpm.TpmApiv4):
        self._connection = tpm_api

    def get_projects_passwords(self, project_ids: List[int]) -> List[Password]:
        result = []

        for project_id in project_ids:
            for password in self.get_project_passwords(project_id):
                result.append(password)

        return result

    def get_project_passwords(self, project_id: int) -> List[Password]:
        password_ids = self.get_projects_password_ids(project_id)

        return self.get_passwords(password_ids)

    def get_projects_password_ids(self, project_id: int) -> List[int]:
        project_passwords_data = self._get_project_password_data(project_id)

        return list(map(lambda p: p.password_id, project_passwords_data))

    def _get_project_password_data(self, project_id: int) -> List[ProjectPassword]:
        result = []

        for item in self._connection.list_passwords_of_project(project_id):
            result.append(ProjectPassword(item['id'], item['name']))

        return result

    def get_certificate_by_project_id(
            self,
            project_id: int,
            name: str
    ) -> Union[Certificate, None]:
        project_passwords_data = self._get_project_password_data(project_id)

        for item in project_passwords_data:
            if item.name == name:
                return self.get_certificate(item.password_id)

        return None

    def save_or_update_certificate(self, tpm_certificate: TpmCertificate) -> int:
        certificate = self.get_certificate_by_project_id(
            project_id=tpm_certificate.project_id,
            name=tpm_certificate.name,
        )

        if certificate is None:
            return self.save_certificate(tpm_certificate)

        self.update_certificate(certificate.id, tpm_certificate)

        return certificate.id

    def save_certificate(self, certificate: TpmCertificate) -> int:
        if certificate.project_id is None:
            raise Exception("Cannot create a certificate, because project_id is missing")

        return self._connection.create_password(
            data=certificate.convert_to_tpm_data_format()
        )

    def update_certificate(self, password_id: int, certificate: TpmCertificate):
        request_data = certificate.convert_to_tpm_data_format()
        del request_data['project_id']

        self._connection.update_password(
            ID=password_id,
            data=request_data
        )

    def get_certificate(self, password_id: int) -> Union[Certificate, None]:
        password_data = self._connection.show_password(password_id)

        def str_to_md5(value: str) -> str:
            return hashlib.md5(value.encode('utf-8')).hexdigest()

        if password_data is None:
            return None

        try:
            ID = password_data['id']
            name = password_data['name']
            md5_cert = str_to_md5(str(password_data['custom_field1']['data']))
            cert = password_data['custom_field1']['data']
            chain = password_data['custom_field2']['data']
            fullchain = password_data['custom_field3']['data']
            privkey = password_data['custom_field4']['data']
        except KeyError:
            return None

        certificate_data = x509.load_pem_x509_certificate(cert.encode('ascii'), default_backend())

        return Certificate(
            ID,
            cert,
            chain,
            fullchain,
            md5_cert,
            name,
            privkey,
            certificate_data.not_valid_after,
            certificate_data.not_valid_before,
        )

    def get_passwords(self, password_ids: List[int]) -> List[Password]:
        hash_map = {}
        result = []

        for password_id in password_ids:
            password = self.get_password(password_id)

            if password is None:
                continue

            hash_map[password.id] = password

        for value in hash_map.values():
            result.append(value)

        return result

    def get_password(self, password_id: int) -> Union[Password, None]:
        data = self._connection.show_password(password_id)  # type: Any

        try:
            password_name = str(data['name'])
            password_id = int(data['id'])
        except KeyError:
            return None

        if password_name == '' or password_id <= 0:
            return None

        if 'password' in data and len(str(data['password'])) > 0:
            return Password(password_id, password_name, str(data['password']))

        if ('custom_field1' in data
                and 'data' in data['custom_field1']
                and len(str(data['custom_field1']['data'])) > 0):
            return Password(password_id, password_name, str(data['custom_field1']['data']))

        if ('custom_field2' in data
                and 'data' in data['custom_field2']
                and len(str(data['custom_field2']['data'])) > 0):
            return Password(password_id, password_name, str(data['custom_field2']['data']))

        return None


class CachingTeamPasswordManager(BaseTeamPasswordManager):
    DEFAULT_CACHE_TTL = int(timedelta(hours=3).total_seconds())

    _team_password_manager: TeamPasswordManager
    _redis_connection: redis.Redis
    _cache_ttl: int
    _secret_box: Union[nacl.secret.SecretBox, None]
    _update_cache: bool

    def __init__(
        self,
        team_password_manager: TeamPasswordManager,
        redis_connection: redis.Redis,
        encryption_key: Union[str, None],
        cache_ttl: int = DEFAULT_CACHE_TTL,
        update_cache: bool = False
    ):
        self._team_password_manager = team_password_manager
        self._redis_connection = redis_connection
        self._update_cache = update_cache
        if cache_ttl is not None and cache_ttl >= 0:
            self._cache_ttl = cache_ttl
        else:
            self._cache_ttl = self.DEFAULT_CACHE_TTL

        if encryption_key is not None:
            self._secret_box = nacl.secret.SecretBox(bytes.fromhex(encryption_key))

    def _add_value_to_cache(self, cache_key: str, value: _CacheValue):
        if self._secret_box is not None:
            value = self._secret_box.encrypt(value.encode())

        self._redis_connection.setex(
            cache_key,
            self._cache_ttl,
            value,
        )

    def _get_value_from_cache(self, cache_key: str) -> Union[_CacheValue, None]:
        if self._update_cache is True:
            return None

        result = self._redis_connection.get(cache_key)
        if result is None:
            return None

        if self._secret_box is not None:
            return self._secret_box.decrypt(result).decode()

        return result

    def get_password(self, password_id: int) -> Union[Password, None]:
        cache_key = generate_password_cache_key(password_id)
        password = self._get_value_from_cache(cache_key)

        if password is not None:
            data = json.loads(password)

            return Password(data['id'], data['name'], data['password'])

        password = self._team_password_manager.get_password(password_id)

        if password is None:
            return None

        self._add_value_to_cache(
            cache_key,
            json.dumps(password.__dict__, default=str)
        )

        return password

    def get_passwords(self, password_ids: List[int]) -> List[Password]:
        result: dict = {}

        for password_id in password_ids:
            if password_id in result:
                continue

            password = self.get_password(password_id)

            if password is not None:
                result[password_id] = password

        return list(result.values())

    def get_projects_passwords(self, project_ids: List[int]) -> List[Password]:
        result = []

        for project_id in project_ids:
            password_ids = self._get_projects_password_ids(project_id)
            result += self.get_passwords(password_ids)

        return result

    def _get_projects_password_ids(self, project_id: int) -> List[int]:
        cache_key = generate_get_projects_password_ids_cache_key(project_id)
        password_ids = self._get_value_from_cache(cache_key)

        if password_ids is not None:
            return json.loads(password_ids)

        password_ids = self._team_password_manager.get_projects_password_ids(project_id)
        self._add_value_to_cache(cache_key, json.dumps(password_ids))

        return password_ids

    def get_certificate_by_project_id(
            self,
            project_id: int,
            name: str
    ) -> Union[Certificate, None]:
        cache_key = generate_certificate_cache_key(project_id, name)
        certificate = self._get_value_from_cache(cache_key)

        if certificate is not None:
            data = json.loads(certificate)

            return Certificate(
                data['id'],
                data['cert'],
                data['chain'],
                data['full_chain'],
                data['md5_cert'],
                data['name'],
                data['private_key'],
                datetime.fromisoformat(data['not_valid_after']),
                datetime.fromisoformat(data['not_valid_before']),
            )

        certificate = self._team_password_manager.get_certificate_by_project_id(project_id, name)

        if certificate is None:
            return None

        self._add_value_to_cache(
            cache_key,
            json.dumps(certificate.__dict__, default=str)
        )

        return certificate

    def get_certificate(self, password_id: int,) -> Union[Certificate, None]:
        cache_key = generate_get_certificate(password_id)
        certificate = self._get_value_from_cache(cache_key)

        if certificate is not None:
            data = json.loads(certificate)

            return Certificate(
                data['id'],
                data['cert'],
                data['chain'],
                data['full_chain'],
                data['md5_cert'],
                data['name'],
                data['private_key'],
                datetime.fromisoformat(data['not_valid_after']),
                datetime.fromisoformat(data['not_valid_before']),
            )

        certificate = self._team_password_manager.get_certificate(password_id)

        if certificate is None:
            return None

        self._add_value_to_cache(
            cache_key,
            json.dumps(certificate.__dict__, default=str)
        )

        return certificate

    def save_or_update_certificate(self, tpm_certificate: TpmCertificate) -> int:
        return self._team_password_manager.save_or_update_certificate(tpm_certificate)
