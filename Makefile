# Directories that might be created during testing
TESTING_DIRS := .tox build dist htmlcov .cache src/pyHIBP.egg-info

build:
	pipenv run python setup.py sdist bdist_wheel

.PHONY: clean
clean:
	find . -type f -name '*.py[co]' -delete

.PHONY: dist-clean
dist-clean: clean
	- pipenv --rm
	if [ -f ".coverage" ]; then rm .coverage; fi
	if [ -f "Pipfile.lock" ]; then rm Pipfile.lock; fi
	- rm -r $(TESTING_DIRS)

.PHONY: dev
dev:
	pipenv install --dev
	pipenv install -e .

.PHONY: test
test:
	pipenv run pytest

.PHONY: test-cov
test-cov:
	pipenv run pytest --cov=pyHIBP test/

.PHONY: check
check:
	pipenv run flake8

.PHONY: tox
tox:
	pipenv run tox
