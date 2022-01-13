.PHONY: test
test:
	. bin/activate && python -m unittest

.PHONY: pylint
pylint:
	. bin/activate && git ls-files | grep .py$$ | xargs pylint

.PHONY: flake8
flake8:
	. bin/activate && git ls-files | grep .py$$ | xargs flake8

.PHONY: lint
lint: flake8 pylint

.PHONY: qa
qa: lint test
