caramel README
==================

Getting Started
---------------

- cd <directory containing this file>

- $venv/bin/python setup.py develop

- $venv/bin/initialize_caramel_db development.ini

- $venv/bin/pserve development.ini


Running Tests
-------------

- cd <directory containing this file>

- $venv/bin/python setup.py develop

- $venv/bin/python -m unittest discover


Running Tests with Nose
-----------------------

- cd <directory containing this file>

- $venv/bin/python setup.py develop

- $venv/bin/pip install nose

- nosetests
