# Blog post
[How we manipulate passwords using Ansible](https://nordsecurity.com/blog/manipulating-passwords-using-ansible)

# Ansible Collection - nordsec.team_password_manager
This collections has a module and filter wrapper for https://teampasswordmanager.com

## Getting started

### Requirements
Make sure that all of the [dependencies](./requirements.txt) are installed.

### Credentials and configuration
In order to use the module or filter you need to create a configuration file with TPM credentials.

Configuration looks like this:

```cfg
[tpm]

[auth:deployuser]
hmac        = False
url         = https://tpm.domain.com
username    = xxxx
password    = xxxx

[auth:deploycertbot]
hmac        = False
url         = https://tpm.domain.com
username    = xxxx
password    = xxxx

[auth:deployadmin]
hmac                 = False
url                  = https://tpm.domain.com
username             = xxxx
password             = xxxx
cache_encryption_key = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
cache_ttl            = 10800
```

The default path of the configuration file is `~/.tpm_password.ini`.

How ever you can provide a custom path via environment variable `TPM_CONFIGURATION_FILE_PATH`

or provide a complete configuration via environment variable `TPM_CONFIGURATION`

### Cache

Cache values will be encrypted only if `cache_encryption_key` is provided and it's a valid 32bit hex string.
The passwords are encrypted using the [PyNaCl: Python binding to the libsodium library](https://pynacl.readthedocs.io/en/latest/)
using the [Secret Key Encryption](https://pynacl.readthedocs.io/en/latest/secret/#secret-key-encryption) approach.

You can generate the `cache_encryption_key` using open `ssl` command like this `openssl rand -hex 32`.

`cache_ttl` options is optional. If this option is not provided, each value will be stored in cache for 3 hours.

## Examples

### Playbook

You can import a debug playbook from this collection to your own and test if everything is working correctly:

```yml
# debug.yml
- import_playbook: nordsec.team_password_manager.debug
```

```shell
ansible-playbook debug.yml
```
