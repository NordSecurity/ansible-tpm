from datetime import datetime


class Password():
    id: int
    name: str
    password: str

    def __init__(self, id: int, name: str, password: str):
        self.id = id
        self.name = name
        self.password = password


class ProjectPassword():
    password_id: int
    name: str

    def __init__(self, password_id: int, name: str):
        self.password_id = password_id
        self.name = name


class TpmCertificate():
    name: str
    cert: str
    chain: str
    full_chain: str
    private_key: str
    project_id: int

    def __init__(
        self,
        name: str,
        cert: str,
        chain: str,
        full_chain: str,
        private_key: str,
        project_id: int,
    ):
        self.project_id = project_id
        self.name = name
        self.cert = cert
        self.chain = chain
        self.full_chain = full_chain
        self.private_key = private_key

    def convert_to_tpm_data_format(self) -> dict:
        result = {
            'custom_data1': self.cert,
            'custom_data2': self.chain,
            'custom_data3': self.full_chain,
            'custom_data4': self.private_key,
            'name': self.name,
            'project_id': self.project_id,
        }

        return result


class Certificate():
    id: int
    cert: str
    chain: str
    full_chain: str
    md5_cert: str
    name: str
    private_key: str
    not_valid_after: datetime
    not_valid_before: datetime

    def __init__(
            self,
            id: int,
            cert: str,
            chain: str,
            full_chain: str,
            md5_cert: str,
            name: str,
            private_key: str,
            not_valid_after: datetime,
            not_valid_before: datetime,
    ):
        self.id = id
        self.cert = cert
        self.chain = chain
        self.full_chain = full_chain
        self.md5_cert = md5_cert
        self.name = name
        self.private_key = private_key
        self.not_valid_after = not_valid_after
        self.not_valid_before = not_valid_before
