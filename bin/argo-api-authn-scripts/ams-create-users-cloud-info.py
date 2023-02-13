#!/usr/bin/env python

import os
import sys
import requests
import json
import defusedxml.ElementTree as ET
import configparser
import logging
import logging.handlers
import argparse
import ldap
import re
import urllib.parse
from argo_ams_library import ArgoMessagingService, AmsUser, AmsUserProject, AmsException, AmsServiceException

# set up logging
LOGGER = logging.getLogger("AMS User create script per site")

ACCEPTED_RDNS = ["CN", "OU", "O", "L", "ST", "C", "DC"]


ACCEPTED_RDNS = [
    "emailAddress", "CN", "OU", "O", "postalCode", "street", "L", "ST", "C", "DC"
]

class RdnSequence(object):
    def __init__(self, rdn_string):

        self.EmailAddress = []
        self.CommonName = []
        self.OrganizationalUnit = []
        self.Organization = []
        self.PostalCode = []
        self.Street = []
        self.Locality = []
        self.Province = []
        self.Country = []
        self.DomainComponent = []

        self._parse_dn_string_ldap_util(rdn_string)

    @staticmethod
    def _rdn_to_type_and_value(rdn_string):
        """
            Processes an rdn and returns its type and value
        """

        if "=" not in rdn_string:
            raise ValueError("Invalid rdn: " + str(rdn_string))

        type_and_value = rdn_string.split("=")

        rdn_type = type_and_value[0]
        rdn_value = type_and_value[1]

        if rdn_type not in ACCEPTED_RDNS:
            raise ValueError("Not accepted rdn : " + str(rdn_type))

        return rdn_type, rdn_value

    def _assign_rdn_to_field(self, rdn_type, rdn_value):
        """
            Assign an RDN value to the correct field based on its type
        """


        if rdn_type == "emailAddress":
            self.EmailAddress.append(rdn_value)

        elif rdn_type == "CN":
            self.CommonName.append(rdn_value)

        elif rdn_type == "OU":
            self.OrganizationalUnit.append(rdn_value)

        elif rdn_type == "O":
            self.Organization.append(rdn_value)

        elif rdn_type == "postalCode":
            self.PostalCode.append(rdn_value)

        elif rdn_type == "street":
            self.Street.append(rdn_value)

        elif rdn_type == "L":
            self.Locality.append(rdn_value)

        elif rdn_type == "ST":
            self.Province.append(rdn_value)

        elif rdn_type == "C":
            self.Country.append(rdn_value)

        elif rdn_type == "DC":
            self.DomainComponent.append(rdn_value)

    @staticmethod
    def _escape_rdn_string(dn_string):
        """
            Method that checks and escapes any possible single slash characters and commas in RDN values

        :param dn_string:
        :return: the escaped string
        """

        re_match_key = re.compile("(\/\w*=)")
        tokens = list(filter(None,re_match_key.split(dn_string)))
        escaped_string = "".join(x.replace("/","\/") if not re_match_key.match(x) else x for x in tokens)

        return escaped_string.replace(",", "\,")

    def _parse_dn_string_ldap_util(self, dn_string):
        """
            Method used to parse RDN string using the ldap functions.
            It also caters to the case of the keyword host/ inside the CN
        """

        # if the host/ appears in the DN
        escaped_dn_string = self._escape_rdn_string(dn_string)

        # check that the DN string is valid and can be parsed
        if not ldap.dn.is_dn(escaped_dn_string, ldap.DN_FORMAT_DCE):
            raise ValueError("DN cannot be parsed with the DN_FORMAT_DCE encoding")

        try:
            rdns_list = ldap.dn.explode_dn(escaped_dn_string, notypes=False, flags=ldap.DN_FORMAT_DCE)
        except Exception as e:
            raise ValueError(str(e))


        # A DN string with the value of /DC=org/DC=terena/DC=tcs/C=DE/O=hosts/O=GermanGrid/OU=DESY/CN=host/example.com
        # will produce the following rdns list
        # ['CN=host/example.com', 'OU=DESY', 'O=GermanGrid', 'O=hosts', 'C=DE', 'DC=tcs', 'DC=terena', 'DC=org']

        # The authn Golang service will produce the following DN string for the above certificate
        # 'CN=host/example.com,OU=DESY,O=hosts+O=GermanGrid,C=DE,DC=org+DC=terena+DC=tcs'

        # In order to have multi-valued RDNs in the order that Authn expects them,
        # e.g. for the RDN DC, DC=org+DC=terena+DC=tcs
        # we need to process the rdn_list from the ldap utility in reverse
        # if we don't, the RDN DC, will look like DC=tcs+DC=terena+DC=org

        for rdn in reversed(rdns_list):
            rdn_type, rdn_value = self._rdn_to_type_and_value(rdn)

            self._assign_rdn_to_field(rdn_type, rdn_value)

    def _parse_dn_string(self, dn_string):
        """
            Method used to parse RDN string manually
        """

        # split the string and skip the empty string of the first slash
        list_of_rdns = dn_string.split("/")[1:]

        # identify the rdn and append the respective list of its values
        for rdn in list_of_rdns:
            rdn_type, rdn_value = self._rdn_to_type_and_value(rdn)

            self._assign_rdn_to_field(rdn_type, rdn_value)

    @staticmethod
    def _format_rdn_to_string(rdn, rdn_values):
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
        # E - CN - OU - O - POSTALCODE - STREET - L - ST - C - DC

        if len(self.EmailAddress) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("E", self.EmailAddress))

        if len(self.CommonName) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("CN", self.CommonName))

        if len(self.OrganizationalUnit) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("OU", self.OrganizationalUnit))

        if len(self.Organization) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("O", self.Organization))

        if len(self.PostalCode) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("POSTALCODE", self.PostalCode))

        if len(self.Street) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("STREET", self.Street))

        if len(self.Locality) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("L", self.Locality))

        if len(self.Province) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("ST", self.Province))

        if len(self.Country) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("C", self.Country))

        if len(self.DomainComponent) != 0:

            if len(printable_string) != 0:
                operator = ","

            printable_string.append(operator)
            printable_string.append(
                self._format_rdn_to_string("DC", self.DomainComponent))

        return "".join(x for x in printable_string)


def create_users(config, verify):

    # retrieve ams info
    ams_host = config.get("AMS", "ams_host")
    ams_project = config.get("AMS", "ams_project")
    ams_token = config.get("AMS", "ams_token")
    ams_email = config.get("AMS", "ams_email")
    users_role = config.get("AMS", "users_role")
    ams_consumer = config.get("AMS", "ams_consumer")
    goc_db_url_arch = config.get("AMS", "goc_db_host")
    goc_db_site_url = "https://goc.egi.eu/gocdbpi/public/?method=get_site&sitename={{sitename}}"

    # retrieve authn info
    authn_host = config.get("AUTHN", "authn_host")
    authn_service_uuid = config.get("AUTHN", "service_uuid")
    authn_token = config.get("AUTHN", "authn_token")
    authn_service_host = config.get("AUTHN", "service_host")

    # dict that acts as a cache for site contact emails
    site_contact_emails = {}

    # cert key tuple
    cert_creds = (config.get("AMS", "cert"), config.get("AMS", "cert_key"))

    # init the Argo Messaging Service
    ams = ArgoMessagingService(endpoint=ams_host, token=ams_token, project=ams_project)

    conf_services = config.get("AMS", "service-types").split(",")
    for srv_type in conf_services:

        # strip any whitespaces
        srv_type = srv_type.replace(" ", "")

        # user count
        user_count = 0

        # updated bindings count
        update_binding_count= 0 

        # updated bindings names
        update_bindings_names= []

        # form the goc db url
        goc_db_url = goc_db_url_arch.replace("{{service-type}}", srv_type)
        LOGGER.info("Accessing url: " + goc_db_url)
        LOGGER.info("Started the process for service-type: " + srv_type)

        # grab the xml data from goc db
        goc_request = requests.get(url=goc_db_url, cert=cert_creds, verify=False)
        LOGGER.info(goc_request.text)

        # users from goc db that don't have a dn registered
        missing_dns = []

        not_in_production_endpoints = []

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

            hostname = service_endpoint.find("HOSTNAME").text.replace(".", "-")
            sitename = service_endpoint.find("SITENAME").text.replace(".", "-")

            # check if the endpoint is in production
            if service_endpoint.find("IN_PRODUCTION").text != "Y":
                LOGGER.info("Skipping not in production endpoint: " + hostname)
                not_in_production_endpoints.append(hostname)
                continue

            # try to get the site's contact email
            contact_email = ams_email
            # check the if we have retrieved this site's contact email before
            site_name = service_endpoint.find("SITENAME").text
            if site_name in site_contact_emails:
                contact_email = site_contact_emails[site_name]
            else:
                try:
                    # try to retrieve the site info from gocdb
                    site_url = goc_db_site_url.replace("{{sitename}}", site_name)
                    goc_site_request = requests.get(site_url, cert=cert_creds, verify=False)
                    site_xml_obj = ET.fromstring(goc_site_request.text)
                    
                    # check if the site is in production
                    in_prod = site_xml_obj.find("SITE").find("PRODUCTION_INFRASTRUCTURE")
                    if in_prod.text != 'Production':
                        raise Exception("Not in production")

                    # check for certified or uncertified
                    cert_uncert = site_xml_obj.find("SITE").find("CERTIFICATION_STATUS")
                    if cert_uncert.text != "Certified" and cert_uncert.text != "Uncertified":
                        raise Exception("Neither certified nor uncertified")

                    contact_email = site_xml_obj.find("SITE").find("CONTACT_EMAIL").text
                    site_contact_emails[site_name] = contact_email

                except Exception as e:
                    LOGGER.warning("Skipping endpoint {0} under site {1}, {2}".format(
                        hostname, site_name, str(e)))

            # Create AMS user
            user_binding_name = \
                service_type + "---" + hostname + "---" + sitename

            # convert the dn
            try:
                service_dn = RdnSequence(service_dn.text).__str__()
            except ValueError as ve:
                LOGGER.error(
                    "Invalid DN: {0}. Exception: {1}".
                    format(service_dn.text, str(ve)))
                continue

            # check if the given DN already corresponds to a binding
            # if the DN is already in use, skip the creation process and only perform the steps where the user
            # is being assigned to the topic's and sub's acl
            # and the respective topic and subscription are being created.

            # TODO replace ams(service type name) with config value
            binding_exists_url = "https://{0}/v1/service-types/ams/hosts/{1}/bindings?key={2}&authID={3}".format(
                authn_host, authn_service_host, authn_token, urllib.parse.quote_plus(service_dn))

            LOGGER.info("Checking if DN {0} is already in use . . . ".format(service_dn))

            binding_exists_req = requests.get(url=binding_exists_url, verify=verify)

            # if the binding exists, retrieve it, and use its name for any further process
            if binding_exists_req.status_code == 200:
                user_binding_name = binding_exists_req.json()["bindings"][0]["name"]
                LOGGER.info("DN {0} is in use by the binding with name {1}".format(service_dn, user_binding_name))

            # else if the Dn isn't in use, go through the full process of creating or updating an existing binding
            elif binding_exists_req.status_code == 404:

                ams_user_uuid = ""

                user_project = AmsUserProject(
                    project=ams_project,
                    roles=[users_role]
                )
                user_create_data = AmsUser(
                    projects=[user_project],
                    email=contact_email,
                    name=user_binding_name
                )

                exists = False
                try:
                    # create the project member user
                    created_ams_user = ams.create_project_member(
                        username=user_binding_name,
                        project=ams_project,
                        roles=[users_role],
                        email=contact_email,
                        verify=verify
                    )
                    LOGGER.info("Created project member user: " + created_ams_user.name)
                    ams_user_uuid = created_ams_user.uuid
                    user_count += 1
                except AmsException as e:
                    if isinstance(e, AmsServiceException) and e.code == 409:
                        exists = True
                    else:
                        LOGGER.error("User: " + user_binding_name)
                        LOGGER.error(
                            "Something went wrong while creating ams project member user." +
                            "\nError: " + str(e))
                        continue

                # If the user already exists, Get user by username
                if exists:
                    try:
                        ams_user_uuid = \
                            ams.get_project_member(username=user_binding_name,
                                                   verify=verify).uuid
                        LOGGER.info("Successfully retrieved user: " + user_binding_name)
                    except AmsException as ae:
                        LOGGER.error(
                            "Could not retrieve user {0} from ams."
                            "\nError: {1}".format(user_binding_name, str(ae)))
                        continue

                # Create the respective AUTH binding
                bd_data = {
                    'service_uuid': authn_service_uuid,
                    'host': authn_service_host,
                    'auth_identifier': service_dn,
                    'unique_key': ams_user_uuid,
                    "auth_type": "x509"
                }

                create_binding_url = "https://{0}/v1/bindings/{1}?key={2}".format(authn_host, user_binding_name, authn_token)

                authn_binding_crt_req = requests.post(url=create_binding_url, data=json.dumps(bd_data), verify=verify)
                LOGGER.info(authn_binding_crt_req.text)

                # if the response is neither a 201(Created) nor a 409(already exists)
                if authn_binding_crt_req.status_code != 201 and authn_binding_crt_req.status_code != 409:
                    LOGGER.critical(
                        "Something went wrong while creating a binding." +
                        "\nBody data: " + str(bd_data) + "\nResponse: " +
                        authn_binding_crt_req.text)
                    continue

                # if the binding already exists, check for an updated DN from gocdb
                if authn_binding_crt_req.status_code == 409:
                    retrieve_binding_url = "https://{0}/v1/bindings/{1}?key={2}".format(authn_host, user_binding_name, authn_token)
                    authn_ret_bind_req = requests.get(url=retrieve_binding_url, verify=verify)
                    # if the binding retrieval was ok
                    if authn_ret_bind_req.status_code == 200:
                        LOGGER.info("\nSuccessfully retrieved binding {} from authn. Checking for DN update.".format(user_binding_name))
                        binding = authn_ret_bind_req.json()
                        # check if the dn has changed
                        if binding["auth_identifier"] != service_dn:
                            # update the respective binding with the new dn
                            bind_upd_req_url = "https://{0}/v1/bindings/{1}?key={2}".format(authn_host, user_binding_name, authn_token)
                            upd_bd_data = {
                                "auth_identifier": service_dn
                            }
                            authn_bind_upd_req = requests.put(url=bind_upd_req_url, data=json.dumps(upd_bd_data), verify=verify)
                            LOGGER.info(authn_bind_upd_req.text)
                            if authn_bind_upd_req.status_code == 200:
                                update_binding_count += 1
                                update_bindings_names.append(user_binding_name)
                    else:
                        LOGGER.critical(
                            "\nCould not retrieve binding {} from authn."
                            "\n Response {}".format(user_binding_name, authn_ret_bind_req.text))
                        continue

            # add the user to the AMS project with corresponding role
            try:
                ams.add_project_member(username=user_binding_name,
                                       roles=[users_role],
                                       verify=verify)
            except AmsException as e:
                if isinstance(e, AmsServiceException) and e.code == 409:
                    pass
                else:
                    LOGGER.error("Could not add user {0} to project {1}.\nError: {2}".format(user_binding_name,
                                                                                             ams_project,
                                                                                             str(e)))
                    continue

            # since both the ams user was created or already existed
            # AND the authn binding was created or already existed
            # move to topic and subscription creation

            # create new topic
            primary_key = service_endpoint. \
                find("PRIMARY_KEY").text.replace(' ', '')
            topic_name = 'SITE_' + sitename + '_ENDPOINT_' + primary_key
            topic_authorized_users = [user_binding_name]
            topic_exists = False

            try:
                ams.create_topic(topic=topic_name, verify=verify)
            except AmsException as e:
                if isinstance(e, AmsServiceException) and e.code == 409:
                    topic_exists = True
                else:
                    LOGGER.error("Could not create topic: {0}.\nError: {1}".format(topic_name, str(e)))
                    continue

            # modify the topic's acl
            # check the already existing acl for the topic
            if topic_exists:
                try:
                    acl = ams.getacl_topic(topic=topic_name, verify=verify)
                    # remove duplicates
                    topic_authorized_users = list(set(topic_authorized_users + acl["authorized_users"]))
                except AmsException as ae:
                    LOGGER.error("Couldn't get ACL for topic {0}.\nError: {1}".format(topic_name, str(ae)))
                    continue

            try:
                ams.modifyacl_topic(topic=topic_name, users=topic_authorized_users, verify=verify)
                LOGGER.info(
                    "Modified ACL for topic: {0} with users {1}.".format(topic_name, str(topic_authorized_users)))
            except AmsException as ae:
                LOGGER.error("Could not modify ACL for topic {0}.\nError: {1}".format(topic_name, str(ae)))
                continue

            # create new sub
            primary_key = service_endpoint.find("PRIMARY_KEY").text.replace(' ', '')
            sub_name = 'SITE_' + sitename + '_ENDPOINT_' + primary_key
            sub_authorized_users = [ams_consumer]
            sub_exists = False

            try:
                ams.create_sub(sub=sub_name,
                               topic=topic_name,
                               ackdeadline=100,
                               verify=verify)
            except AmsException as e:
                if isinstance(e, AmsServiceException) and e.code == 409:
                    sub_exists = True
                else:
                    LOGGER.error("Could not create sub: {0}.\nError: {1}".format(sub_name, str(e)))
                    continue

            # modify the sub's acl
            # check the already existing acl for the subscription
            if sub_exists:
                try:
                    acl = ams.getacl_sub(sub=sub_name, verify=verify)
                    # remove duplicates
                    sub_authorized_users = list(set(sub_authorized_users + acl["authorized_users"]))
                except AmsException as ae:
                    LOGGER.error("Couldn't get ACL for sub {0}.\nError: {1}".format(sub_name, str(ae)))
                    continue

            try:
                ams.modifyacl_sub(sub=sub_name, users=sub_authorized_users, verify=verify)
                LOGGER.info(
                    "Modified ACL for sub: {0} with users {1}.".format(sub_name, str(sub_authorized_users)))
            except AmsException as ae:
                LOGGER.error("Could not modify ACL for sub {0}.\nError: {1}".format(sub_name, str(ae)))
                continue

        LOGGER.info("Service Type: " + srv_type)
        LOGGER.critical("Missing DNS: " + str(missing_dns))
        LOGGER.critical("Not in production endpoints: " +str(not_in_production_endpoints))
        LOGGER.info("Total Users Created: " + str(user_count))
        LOGGER.info("Total Bindings Updated: " + str(update_binding_count))
        LOGGER.info("Updated bingings: " + str(update_bindings_names))


def main(args=None):

    # set up the config parser
    config = configparser.ConfigParser()

    # check if config file has been given as cli argument else
    # check if config file resides in /etc/argo-api-authn/ folder else
    # check if config file resides in local folder
    if args.ConfigPath is None:
        cfg_file = "/etc/argo-api-authn/conf.d/ams-create-users-cloud-info.cfg"
        if os.path.isfile(cfg_file):
            config.read(cfg_file)
        else:
            config.read("../../conf/ams-create-users-cloud-info.cfg")
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