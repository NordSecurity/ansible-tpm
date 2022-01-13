.PHONY: test
test:
	. bin/activate && ansible-test units --color --local --python 3.8

.PHONY: pylint
pylint:
	. bin/activate && pylint plugins && pylint tests

.PHONY: flake8
flake8:
	. bin/activate && flake8 plugins && flake8 plugins

.PHONY: lint
lint: flake8 pylint

.PHONY: qa
qa: lint test ansible-test

.PHONY: debug-get-password
debug-get-password:
	. bin/activate && python plugins/modules/team_password_manager.py \
							 plugins/modules/tpm_module_test_args.json

.PHONY: debug-mix
debug-mix:
	. bin/activate && python plugins/modules/team_password_manager.py \
							 plugins/modules/tpm_module_test_args_mix.json

.PHONY: debug-get-cert-from-project
debug-get-cert-from-project:
	. bin/activate && python plugins/modules/team_password_manager.py \
							 plugins/modules/tpm_module_test_args_cert.json

.PHONY: ansible-test-docker # currently not working
ansible-test-docker:
	. bin/activate && ansible-test units --color --docker default --coverage
