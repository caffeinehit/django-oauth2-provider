.DEFAULT_GOAL := test

.PHONY: html_coverage, quality, requirements

html_coverage:
	coverage html && open htmlcov/index.html

requirements:
	pip install -r requirements.txt

test:
	coverage run --branch --source=provider manage.py test provider provider.oauth2
	coverage report
