from setuptools import setup, find_packages

setup(
    name='caramel-request-cert',
    version='0.1',
    packages=find_packages(),
    scripts=['request-cert'],

    install_requires=['requests']
)
