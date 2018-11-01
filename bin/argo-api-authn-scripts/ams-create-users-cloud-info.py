#!/usr/bin/env python

import os
import sys
import requests
import json
import defusedxml.ElementTree as ET
import ConfigParser
import logging
import logging.handlers
import argparse

# set up logging
LOGGER = logging.getLogger("AMS User create script per site")

ACCEPTED_RDNS = ["CN", "OU", "O", "L", "ST", "C", "DC"]


class RdnSequence(object):
    def __init__(self, rdnstring):

        self.CommonName = []
        self.OrganizationalUnit = []
        self.Organization = []
        self.Locality = []
        self.Province = []
        self.Country = []
        self.DomainComponent = []

        # split the string and skip the empty string of the first slash
        list_of_rdns = rdnstring.split("/")[1:]

        # identify the rdn and append the respective list of its values
        for rdn in list_of_rdns:

            if "=" not in rdn:
                raise ValueError("Invalid rdn: " + str(rdn))

            type_and_value = rdn.split("=")

            rdn_type = type_and_value[0]
            rdn_value = type_and_value[1]

            if rdn_type not in ACCEPTED_RDNS:
                raise ValueError("Not accepted rdn : " + str(rdn_type))

            if rdn_type == "CN":
                self.CommonName.append(rdn_value)
                continue

            if rdn_type == "OU":
                self.OrganizationalUnit.append(rdn_value)
                continue

            if rdn_type == "O":
                self.Organization.append(rdn_value)
                continue

            if rdn_type == "L":
                self.Locality.append(rdn_value)
                continue

            if rdn_type == "ST":
                self.Province.append(rdn_value)
                continue

            if rdn_type == "C":
                self.Country.append(rdn_value)
                continue

            if rdn_type == "DC":
                self.DomainComponent.append(rdn_value)
                continue

    def format_rdn_to_string(self, rdn, rdn_values):
        """
        Take as input an RDN and its values
        and convert them to a printable string
        Attributes:
            rdn(str): The name of the RDN of the provided values
            rdn_values(list): list containing the values of the given RDN
        Returns:
            (str): String representation of the rdn combined with its values
        Example:
            rdn: DC
            rdn_values: [argo, grnet, gr]
            return: DC=argo+DC=grnet+DC=gr
        """

        # operator is a string literal that stands
        # between the values of the given RDN
        operator = ""

        printable_string = []

        for rdn_value in rdn_values:

            # if the string is empty, we should use no operator
            # since there are no values present in the string
            if len(printable_string) != 0:
                operator = "+"

            printable_string.append(operator)
            printable_string.append(rdn)
            printable_string.append("=")
            printable_string.append(rdn_value)

        return "".join(x for x in printable_string)

    def __str__(self):

        printable_string = []

        # operator is a string literal that stands between the values
        # of the RDNs. If the string is empty, we should use no operator
        # since there are no values present in the string
        operator = ""

        # we check if a specific RDN holds any values and we concatenate
        # it with the previous RDN using a comma ','
        # RDNs must follow the specific order of:
        # CN - OU - O - L -ST - C - DC

        if len(self.CommonName) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self.format_rdn_to_string("CN", self.CommonName))

        if len(self.OrganizationalUnit) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self.format_rdn_to_string("OU", self.OrganizationalUnit))

        if len(self.Organization) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self.format_rdn_to_string("O", self.Organization))

        if len(self.Locality) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self.format_rdn_to_string("L", self.Locality))

        if len(self.Province) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self.format_rdn_to_string("ST", self.Province))

        if len(self.Country) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self.format_rdn_to_string("C", self.Country))

        if len(self.DomainComponent) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self.format_rdn_to_string("DC", self.DomainComponent))

        return "".join(x for x in printable_string)


def create_users(config, verify):

    # retrieve ams info
    ams_host = config.get("AMS", "ams_host")
    ams_project = config.get("AMS", "ams_project")
    ams_token = config.get("AMS", "ams_token")
    ams_email = config.get("AMS", "ams_email")
    users_role = config.get("AMS", "users_role")
    goc_db_url_arch = config.get("AMS", "goc_db_host")

    # retrieve authn info
    authn_host = config.get("AUTHN", "authn_host")
    authn_service_uuid = config.get("AUTHN", "service_uuid")
    authn_token = config.get("AUTHN", "authn_token")
    authn_service_host = config.get("AUTHN", "service_host")

    # services holds all different services that the users
    # might belong to(which translates to ams topics)
    # each service will have a list of users associated with it
    services = {}
    conf_services = config.get("AMS", "service-types").split(",")
    for srv_type in conf_services:

        # strip any whitespaces
        srv_type = srv_type.replace(" ", "")

        # user count
        user_count = 0

        # form the goc db url
        goc_db_url = goc_db_url_arch.replace("{{service-type}}", srv_type)
        LOGGER.info("\nAccessing url: " + goc_db_url)
        LOGGER.info("\nStarted the process for service-type: " + srv_type)

        # grab the xml data from goc db
        goc_request = requests.get(goc_db_url, verify=False)
        LOGGER.info(goc_request.text)

        # users from goc db that don't have a dn registered
        missing_dns = []

        # srv_type
        srv_type = srv_type.replace(".", "-")
        services[srv_type] = []

        # build the xml object
        root = ET.fromstring(goc_request.text)
        # iterate through the xml object's service_endpoints
        for service_endpoint in root.findall("SERVICE_ENDPOINT"):
            service_type = service_endpoint.find("SERVICE_TYPE"). \
                text.replace(".", "-")

            # grab the dn
            service_dn = service_endpoint.find("HOSTDN")
            if service_dn is None:
                missing_dns.append(service_endpoint.find("HOSTNAME").text)
                continue

            # Create AMS user
            hostname = service_endpoint.find("HOSTNAME").text.replace(".", "-")
            sitename = service_endpoint.find("SITENAME").text.replace(".", "-")
            user_binding_name = \
                service_type + "---" + hostname + "---" + sitename

            # convert the dn
            try:
                service_dn = RdnSequence(service_dn.text).__str__()
            except ValueError as ve:
                LOGGER.error(
                    "Invalid DN: {}. Exception: {}".
                    format(service_dn.text, ve.message))
                continue

            project = {'project': ams_project, 'roles': [users_role]}
            usr_create = {'projects': [project], 'email': ams_email}

            # create the user
            ams_usr_crt_req = requests.post(
                "https://" + ams_host + "/v1/users/" + user_binding_name +
                "?key=" + ams_token,
                data=json.dumps(usr_create), verify=verify)
            LOGGER.info(ams_usr_crt_req.text)

            # if the response doesn't contain the field uuid,
            # it means the user was not created
            req_data = json.loads(ams_usr_crt_req.text)
            if ams_usr_crt_req.status_code != 200:
                LOGGER.critical("\nUser: " + user_binding_name)
                LOGGER.critical(
                    "\nSomething went wrong while creating ams user." +
                    "\nBody data: " + str(usr_create) + "\nResponse Body: " +
                    ams_usr_crt_req.text)
            if "uuid" not in req_data:
                LOGGER.critical("uuid field not found in response from ams")
                continue

            # Create the respective AUTH binding
            bd_data = {
                'name': user_binding_name,
                'service_uuid': authn_service_uuid,
                'host': authn_service_host,
                'dn': service_dn,
                'unique_key': req_data["uuid"]
            }
            authn_binding_crt_req = requests.post(
                "https://"+authn_host+"/v1/bindings?key="+authn_token,
                data=json.dumps(bd_data), verify=verify)
            LOGGER.info(authn_binding_crt_req.text)

            if authn_binding_crt_req.status_code != 201:
                LOGGER.critical(
                    "Something went wrong while creating a binding." +
                    "\nBody data: " + str(bd_data) + "\nResponse: " +
                    authn_binding_crt_req.text)
                # delete the ams user, since binding could not be created
                requests.delete(
                    "https://" + ams_host + "/v1/users/" + user_binding_name +
                    "?key=" + ams_token, verify=verify)
                continue

            # if both the user and binding have been created,
            # assign the user to the acl of the topic
            services[service_type].append(user_binding_name)

            # count how many users have been created
            user_count += 1

            # create new topic
            primary_key = service_endpoint. \
                find("PRIMARY_KEY").text.replace(' ', '')
            topic_name = 'SITE_' + sitename + '_ENDPOINT_' + primary_key
            topic_crt_req = requests.put(
                "https://" + ams_host + "/v1/projects/" + ams_project +
                "/topics/" + topic_name + "?key=" + ams_token, verify=verify)
            if topic_crt_req.status_code != 200:
                LOGGER.critical(
                    "Something went wrong while creating topic " +
                    topic_name + "\nResponse: " + topic_crt_req.text)
                continue

            # modify the authorized users
            modify_topic_req = requests.post(
                "https://" + ams_host + "/v1/projects/" + ams_project +
                "/topics/" + topic_name + ":modifyAcl?key=" + ams_token,
                data=json.dumps({'authorized_users': [user_binding_name]}),
                verify=verify)
            LOGGER.critical(
                "Modified ACL for topic: {} with users {}. " +
                "Response from AMS {}".
                format(
                    topic_name, str(user_binding_name), modify_topic_req.text))

        # modify the acl for each topic , to add all associated users
        authorized_users = services[srv_type]
        if len(authorized_users) != 0:

            get_topic_acl_req = requests.get(
                "https://" + ams_host + "/v1/projects/" + ams_project +
                "/topics/" + srv_type + ":acl?key=" + ams_token, verify=verify)

            if get_topic_acl_req.status_code == 200:
                acl_users = json.loads(get_topic_acl_req.text)
                authorized_users = \
                    authorized_users + acl_users["authorized_users"]
                modify_topic_acl_req = requests.post(
                    "https://" + ams_host + "/v1/projects/" + ams_project +
                    "/topics/" + srv_type + ":modifyAcl?key=" + ams_token,
                    data=json.dumps({'authorized_users': authorized_users}),
                    verify=verify)
                LOGGER.critical(
                    "Modified ACL for topic: {} with users {}. " +
                    "Response from AMS {}".format(
                        srv_type, str(authorized_users),
                        modify_topic_acl_req.text))
            else:
                LOGGER.critical(
                    "Couldn't get ACL for topic {}. Response from AMS {}".
                    format(srv_type, get_topic_acl_req.text))

        LOGGER.critical("Service Type: " + srv_type)
        LOGGER.critical("Missing DNS: " + str(missing_dns))
        LOGGER.critical("Total Users Created: " + str(user_count))
        LOGGER.critical("-----------------------------------------")


def main(args=None):

    # set up the config parser
    config = ConfigParser.ConfigParser()

    # check if config file has been given as cli argument else
    # check if config file resides in /etc/argo-api-authn/ folder else
    # check if config file resides in local folder
    if args.ConfigPath is None:
        cfg_file = "/etc/argo-api-authn/conf.d/ams-create-users-gocdb.cfg"
        if os.path.isfile(cfg_file):
            config.read(cfg_file)
        else:
            config.read("../../conf/ams-create-users-gocdb.cfg")
    else:
        config.read(args.ConfigPath)

    # stream(console) handler
    console_handler = logging.StreamHandler()
    LOGGER.addHandler(console_handler)
    LOGGER.setLevel(logging.INFO)

    # sys log handler
    syslog_handler = logging.handlers.SysLogHandler(
        config.get("LOGS", "syslog_socket"))
    syslog_handler.setFormatter(
        logging.Formatter('%(name)s[%(process)d]: %(levelname)s %(message)s'))
    syslog_handler.setLevel(logging.WARNING)
    LOGGER.addHandler(syslog_handler)

    # start the process of creating users
    create_users(config, args.Verify)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Create ams users and their respective bindings " +
        "using data imported from goc db")
    parser.add_argument(
        "-c", "--ConfigPath", type=str, help="Path for the config file")
    parser.add_argument(
        "-verify", "--Verify", help="SSL verification for requests",
        action="store_true")

    sys.exit(main(parser.parse_args()))
