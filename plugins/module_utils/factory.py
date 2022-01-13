import configparser
import os
import redis
from ansible_collections.nordsec.team_password_manager.plugins.module_utils.manager import (
    TeamPasswordManager,
    CachingTeamPasswordManager,
    BaseTeamPasswordManager
)
import tpm

ENV_VARIABLE_TPM_CONFIGURATION = "TPM_CONFIGURATION"
ENV_VARIABLE_TPM_CONFIGURATION_FILE_PATH = "TPM_CONFIGURATION_FILE_PATH"
DEFAULT_TPM_CONFIGURATION_FILE_PATH = "~/.tpm_password.ini"

CONFIG_CACHE_OPTION_ENCRYPTION_KEY = "cache_encryption_key"
CONFIG_CACHE_OPTION_CACHE_TTL = "cache_ttl"


def _parse_config_from_file(file_path: str) -> configparser.ConfigParser:
    if os.path.isfile(file_path) is False:
        raise Exception('Could not find configration file at %s' % (file_path))

    config = configparser.ConfigParser()
    config.read(file_path)

    return config


def _parse_config(config_data: str):
    config = configparser.ConfigParser()
    config.read_string(config_data)

    return config


def _create_connection(
    config: configparser.ConfigParser,
    section: str
) -> tpm.TpmApiv4:
    url = config.get(section, 'url')

    if config.getboolean(section, 'hmac'):
        return tpm.TpmApiv4(
            url,
            private_key=config.get(section, 'private_key'),
            public_key=config.get(section, 'public_key'),
        )

    return tpm.TpmApiv4(
        url,
        username=config.get(section, 'username'),
        password=config.get(section, 'password'),
    )


def _create_config_from_file() -> configparser.ConfigParser:
    file_path = os.environ.get(ENV_VARIABLE_TPM_CONFIGURATION_FILE_PATH)

    if file_path is None:
        file_path = DEFAULT_TPM_CONFIGURATION_FILE_PATH

    return _parse_config_from_file(file_path)


def _create_config_from_env_variable() -> configparser.ConfigParser:
    data = os.environ.get(ENV_VARIABLE_TPM_CONFIGURATION)

    if data is None:
        raise Exception(
            'Could not load configration because %s variable is empty or does not exist' %
            (ENV_VARIABLE_TPM_CONFIGURATION)
        )

    return _parse_config(data)


class TpmApiFactory():
    def create(self, configuration_section: str) -> tpm.TpmApiv4:
        if os.environ.get(ENV_VARIABLE_TPM_CONFIGURATION, ""):
            return self.create_from_env_variable(configuration_section)

        return self.create_from_file(configuration_section)

    def create_from_file(self, configuration_section: str) -> tpm.TpmApiv4:
        return _create_connection(_create_config_from_file(), configuration_section)

    def create_from_env_variable(self, configuration_section: str) -> tpm.TpmApiv4:
        return _create_connection(_create_config_from_env_variable(), configuration_section)


class TeamPasswordManagerFactory():
    def _get_config(self) -> configparser.ConfigParser:
        if os.environ.get(ENV_VARIABLE_TPM_CONFIGURATION, ""):
            return _create_config_from_env_variable()

        return _create_config_from_file()

    def create(
        self,
        configuration_section: str,
        update_cache: bool = False
    ) -> BaseTeamPasswordManager:
        tpm_api = (TpmApiFactory()).create(configuration_section)

        redis_connection = redis.StrictRedis()
        password_manager = TeamPasswordManager(tpm_api)

        config = self._get_config()
        if config.has_option(configuration_section, CONFIG_CACHE_OPTION_ENCRYPTION_KEY):
            cache_ttl = config.get(
                section=configuration_section,
                option=CONFIG_CACHE_OPTION_CACHE_TTL,
                fallback=None
            )

            encryption_key = config.get(
                section=configuration_section,
                option=CONFIG_CACHE_OPTION_ENCRYPTION_KEY,
                fallback=None
            )

            if cache_ttl is not None:
                cache_ttl = int(cache_ttl)

            try:
                redis_connection.ping()
                password_manager = CachingTeamPasswordManager(
                    password_manager,
                    redis_connection,
                    encryption_key,
                    cache_ttl,
                    update_cache
                )
            except (
                redis.exceptions.ConnectionError,
                redis.exceptions.BusyLoadingError
            ):
                pass

        return password_manager
