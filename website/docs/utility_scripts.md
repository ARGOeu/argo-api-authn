---
id: utility_scripts
title: Utility Scripts
sidebar_position: 8
---

# Python utility scripts for easier interaction with the service

| Script | Description | Shortcut |
|--------|-------------|---------- |
| ams-create-users-gocdb.py | Python script that creates ams users and binding.| [Details](#ams-create-users-gocdb) |
| ams-create-users-cloud-info.py | Python script that creates ams users, binding and topics per site.| [Details](#ams-create-users-cloud-info) |


## AMS Create users from goc db script {#ams-create-users-gocdb}


Python utility script that takes the xml feed from goc db,creates the respective
ams users under the specified project, assigns to the correct project's topic and
finally creates the binding for each user, using the dn from goc db.

`ams-create-users-gocdb.py -c <ConfigPath> -verify`

`-c : Path to an appropriate config file.If not specified
it will first look at /etc/argo-api-authn/conf.d/ams-users-create-gocdb.cfg
and then will look at projects conf folder`

`-verify: If specified all the requests will check the validity of the ssl certificate`


## AMS Create users and topics per site {#ams-create-users-cloud-info}


Python utility script that takes an xml feed from goc db, creates the respective
ams users under the specified project, assigns to the correct project's topic, 
creates the binding for each user, using the dn from goc db and finally creates 
topics with the schema SITE\_`sitename`\_ENDPOINT\_`id_in_gocdb`.

`ams-create-users-cloud-info.py -c <ConfigPath> -verify`

`-c : Path to an appropriate config file.If not specified
it will first look at /etc/argo-api-authn/conf.d/ams-create-users-cloud-info.cfg
and then will look at projects conf folder`

`-verify: If specified all the requests will check the validity of the ssl certificate`

## Configuration
Use the `ams-create-users-gocdb.template` or `ams-create-users-cloud-info.template`
respectively to produce your conf file.
The project should exist in AMS in advance.
The service types specified should also be present as topics in ams under the specified project
```buildoutcfg
[AMS]
# under which ams project, the users will be created
ams_project:
# goc db url to pull user data
goc_db_host:
# service types referes to the different service types that will we should keep from the xml and assign them to the respectivew ams topic 
service-types:
# cert to access gocdb
cert: /path/to/cert
cert_key: /path/to/key
# ams use role
users_role: publisher
# token to access ams
ams_token:
# ams url
ams_host:
# ams user email - since we don't get an email from goc db, we can use this field as a wildcard, to identify which users were created with this script
ams_email: goc_db_user

[AUTHN]
# token to access authn
authn_token:
# authn url to create bindings
authn_host: 
# service's uuid where bindings will belong
service_uuid:
# service's host where bindings will belong
service_host:

[LOGS]
syslog_socket:
```

## Requirements
There is a requirements.txt file inside the repo's `bin` folder that specifies which dependencies are needed.

If you don't want to manually handle the dependencies, you can use the setup.py script in the root folder of the repo.

`python setup.py install`  

OR

`pip install git+https://github.com/ARGOeu/argo-api-authn.git@devel` for the latest release

`pip install git+https://github.com/ARGOeu/argo-api-authn.git` for the stable release


After installing the script's package, you can find them in the `/usr/bin` or if you are using a virtualenv in the `bin` folder of the virtualenv.

In addition, if you want to use them in other scripts, you will can import them:
```python
import argo_api_authn_scripts   
```
