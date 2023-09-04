"""Certbot Authenticator Plugin for Opteamax DNS.

@author:     Peter Lieven <pl@opteamax.de>
@license:    GPL

"""
import logging
import json
import time

from certbot import interfaces, errors
from certbot.plugins import common
from certbot.plugins import dns_common
from urllib.request import urlopen, Request

logger = logging.getLogger(__name__)

OXAPI_URL = "https://www.opteamax.de/oxapi/dns/"
REQUEST_TIMEOUT_S = 60

class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Opteamax DNS

    This Authenticator uses the Opteamax OXAPI API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are '
                   'using Opteamax for DNS).')
    
    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds = 180)
        add('credentials', help='Opteamax OXAPI credentials INI file.')

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Opteamax OXAPI credentials INI file',
            {
                'username':      'OXAPI Username',
                'password':      'OXAPI Password',
            }
        )

    def more_info(self):
        return ('This plugin configures a DNS TXT record to respond to a '
                'dns-01 challenge using the Opteamax OXAPI.')

    def _call_oxapi(self, command, data):
        logger.debug("_call_oxapi: calling %s%s with %s" % (OXAPI_URL, command, data))
        req = Request("%s%s" % (OXAPI_URL, command))
        req.add_header('Content-Type', 'application/json')
        res = urlopen(req, json.dumps(data).encode('utf-8'), REQUEST_TIMEOUT_S)
        data = res.read().decode('utf-8')
        logger.debug("_call_oxapi: response -> %s\n" % data)
        jsonRes = json.loads(data)
        if (type(jsonRes) is dict and jsonRes['errno'] is not None and int(jsonRes['errno']) != 0):
            raise errors.PluginError(
                "OXAPI returned error: {}".format(jsonRes))
        return jsonRes

    def _build_ox_auth(self):
        return {'user': self.credentials.conf("username"), 'passwd': self.credentials.conf("password")}

    def _get_ox_domid(self, domain: str) -> (int, str, str):
        logger.debug("_get_ox_domid: domain %s", domain)
        params = { 'auth': self._build_ox_auth(), 'with_ptr': False }
        res = self._call_oxapi('get_zones', params)
        domid = 0
        longestMatch = ""
        for row in res:
            suffixLen = len(row['domain']) + 1
            if (suffixLen > len(domain)):
                continue
            suffix = domain[-suffixLen:]
            if (suffix == "." + row['domain']):
                if (len(row['domain']) > len(longestMatch)):
                    longestMatch = row['domain']
                    domid = row['domain_id']
        if (domid == 0):
            raise errors.PluginError(
                "Could not find OXAPI domid for certiciate domain: {}".format(domain))
        localPart = domain[0:len(domain) - len(longestMatch) - 1]
        logger.debug("_get_ox_domid: found id %d for localPart '%s' longestMatch '%s'", domid, localPart, longestMatch)
        return (domid, longestMatch, localPart)

    def _rm_ox_record(self, dataid) -> None:
        logger.debug("_rm_ox_record: dataid %d", dataid)
        params = { 'auth': self._build_ox_auth(), 'record': dataid }
        self._call_oxapi('delete_record', params)

    def _rm_ox_txt_rr(self, domid, localPart) -> None:
        logger.debug("_rm_ox_txt_rr: domid %d localPart %s", domid, localPart)
        params = { 'auth': self._build_ox_auth(), 'domain_id': domid }
        res = self._call_oxapi('get_entries', params)
        for row in res['data']:
            if (row['subdomain'] == localPart):
                logger.debug('_rm_ox_txt_rr: need to delete orphan RR %d subdomain %s target %s', row['dataid'], row['subdomain'], row['target'])
                self._rm_ox_record(row['dataid'])

    def _add_ox_txt_rr(self, domid, fqdn, text) -> None:
        logger.debug("_add_ox_txt_rr: domid %d fqdn %s text %s", domid, fqdn, text)
        data = {
            'type' : 'TXT',
            'fqdn' : fqdn,
            'text' : text,
            'ttl' : 300,
            'id' : 0,
        }
        params = { 'auth': self._build_ox_auth(), 'domainid': domid, 'data' : json.dumps(data) }
        self._call_oxapi('save_record', params)

    def _perform(self, domain, validation_name, validation):
        logger.debug("_perform: domain %s validation_name %s validation %s", domain, validation_name, validation)
        (domid, longestMatch, localPart) = self._get_ox_domid(validation_name)
        self._rm_ox_txt_rr(domid, localPart)
        self._add_ox_txt_rr(domid, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        logger.debug("_cleanup: domain %s validation_name %s validation %s", domain, validation_name, validation)
        (domid, longestMatch, localPart) = self._get_ox_domid(validation_name)
        self._rm_ox_txt_rr(domid, localPart)
