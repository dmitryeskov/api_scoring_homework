unit-tests:
	pytest -v tests/unit/test.py

functional-tests:
	pytest -v tests/functional/test.py

format:
	black .
