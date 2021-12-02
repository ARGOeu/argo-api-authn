from setuptools import setup

NAME = "argo-api-authn-scripts"

setup(
    name=NAME,
    version="1",
    author='GRNET',
    description='Collection of useful scripts for interacting with the argo api authn service',
    long_description='Collection of useful scripts for interacting with the argo api authn service',
    url='https://github.com/ARGOeu/argo-api-authn',
    scripts=['./bin/argo-api-authn-scripts/ams-create-users-gocdb.py',
        './bin/argo-api-authn-scripts/ams-create-users-cloud-info.py'],
    package_dir={'argo_api_authn_scripts': './bin/argo-api-authn-scripts/'},
    packages=['argo_api_authn_scripts'],
    install_requires=['defusedxml==0.5.0', 'requests==2.20', 'python-ldap==3.4.0']
    )
