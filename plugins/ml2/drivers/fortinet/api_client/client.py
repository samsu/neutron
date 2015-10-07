# Copyright 2015 Fortinet, Inc.
#
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import httplib
import json
from Cheetah.Template import Template


from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.fortinet.api_client import base
from neutron.plugins.ml2.drivers.fortinet.api_client import eventlet_client
from neutron.plugins.ml2.drivers.fortinet.api_client import eventlet_request
from neutron.plugins.ml2.drivers.fortinet.api_client import exception
from neutron.plugins.ml2.drivers.fortinet.api_client import templates


LOG = logging.getLogger(__name__)


class FortiosApiClient(eventlet_client.EventletApiClient):
    """The FortiOS API Client."""

    def __init__(self, api_providers, user, password,
                 concurrent_connections=base.DEFAULT_CONCURRENT_CONNECTIONS,
                 gen_timeout=base.GENERATION_ID_TIMEOUT,
                 use_https=False,
                 connect_timeout=base.DEFAULT_CONNECT_TIMEOUT,
                 http_timeout=75, retries=2, redirects=2):
        '''Constructor. Adds the following:

        :param http_timeout: how long to wait before aborting an
            unresponsive controller (and allow for retries to another
            controller in the cluster)
        :param retries: the number of concurrent connections.
        :param redirects: the number of concurrent connections.
        '''
        super(FortiosApiClient, self).__init__(
            api_providers, user, password,
            concurrent_connections=concurrent_connections,
            gen_timeout=gen_timeout, use_https=use_https,
            connect_timeout=connect_timeout)

        self._request_timeout = http_timeout * retries
        self._http_timeout = http_timeout
        self._retries = retries
        self._redirects = redirects
        self._version = None
        self.message = {}
        self._user = user
        self._password = password

    @staticmethod
    def _render(template, **message):
        '''Render API message from it's template

        :param template: defined API message with essential params.
        :param message: It is a dictionary, included values of the params
                        for the template
        '''
        if not message:
            message = {}
        LOG.debug(_("##### message=%s" % message))
        return json.loads(unicode(Template(template, message)))


    def msg_login(self, user, password):
        '''Login to Fortigate.

        Assumes same password is used for all controllers.
        :param user: controller user (usually admin). Provided for
                backwards compatibility. In the  normal mode of operation
                this should be None.
        :param password: controller password. Provided for backwards
                compatibility. In the normal mode of operation this should
                be None.
        '''
        if user:
            userinfo = {
                "username": user,
                "secretkey": password
            }
            #return self._render(templates.LOGIN, userinfo)
            message = self._render(templates.LOGIN, username=user, secretkey=password)
            return message
        LOG.error(_('No username was assigned, username:%(username)s '
                    'and password:%(password)s'),
                  {'username': self._user, 'password': self._password})


    def logout(self):
        '''Login to Fortigate.

        Assumes same password is used for all controllers.
        :param user: controller user (usually admin). Provided for
                backwards compatibility. In the  normal mode of operation
                this should be None.
        :param password: controller password. Provided for backwards
                compatibility. In the normal mode of operation this should
                be None.
        '''
        self.request("LOGOUT")


    def request(self, opt, content_type="application/json", **message):
        '''Issues request to controller.'''
        #print "opt = %s" % opt
        #print "message = %s" % message
        self.message = self._render(getattr(templates, opt), **message)
        method = self.message['method']
        url = self.message['path']
        body = self.message['body'] if 'body' in self.message else None
        g = eventlet_request.GenericRequestEventlet(
            self, method, url, body, content_type, auto_login=True,
            http_timeout=self._http_timeout,
            retries=self._retries, redirects=self._redirects)
        g.start()
        response = g.join()

        # response is a modified HTTPResponse object or None.
        # response.read() will not work on response as the underlying library
        # request_eventlet.ApiRequestEventlet has already called this
        # method in order to extract the body and headers for processing.
        # ApiRequestEventlet derived classes call .read() and
        # .getheaders() on the HTTPResponse objects and store the results in
        # the response object's .body and .headers data members for future
        # access.

        if response is None:
            # Timeout.
            LOG.error(_('Request timed out: %(method)s to %(url)s'),
                      {'method': method, 'url': url})
            raise exception.RequestTimeout()

        status = response.status
        if status == httplib.UNAUTHORIZED:
            raise exception.UnAuthorizedRequest()
        # Fail-fast: Check for exception conditions and raise the
        # appropriate exceptions for known error codes.
        if status in exception.ERROR_MAPPINGS:
            LOG.error(_("Received error code: %s"), status)
            LOG.error(_("Server Error Message: %s"), response.body)
            exception.ERROR_MAPPINGS[status](response)

        # Continue processing for non-error condition.
        if (status != httplib.OK and status != httplib.CREATED
                and status != httplib.NO_CONTENT):
            LOG.error(_("%(method)s to %(url)s, unexpected response code: "
                        "%(status)d (content = '%(body)s')"),
                      {'method': method, 'url': url,
                       'status': response.status, 'body': response.body})
            return None

        if url == json.loads(templates.LOGOUT)['path']:
            return response.body
        else:
            return json.loads(response.body)


if __name__ == "__main__":
    import time
    api = [("10.160.37.95", 80, False)]
    user = "admin"
    password = ""
    cli = FortiosApiClient(api, user, password)
    print "----------"
    message = {
        "name": "ext_4093",
        "vlanid": 4093,
        "vdom": "root",
        "interface": "port1",
        "ip": "192.168.30.254 255.255.255.0"
    }
    cli.request("ADD_VLAN_INTERFACE", **message)
    message = {
        "name": "port5",
        "vdom": "root",
        "ip": "192.168.40.254 255.255.255.0"
        #"secondaryips": ["192.168.20.200 255.255.255.0", ]
        #"secondaryips": []
    }
    #print cli.request("SET_VLAN_INTERFACE", **message)
    message = {
        "name": "ext_4093"
    }

    print cli.request("GET_VLAN_INTERFACE", **message)

    #print "mac_address =",res["results"][0]["macaddr"]
    cli.request("DELETE_VLAN_INTERFACE", **message)
    message = {
        "vdom": "osvdm15",
        "interface": "os_vid_1009",
        "gateway": "192.168.30.1",
        "netmask": "255.255.255.0",
        "start_ip": "192.168.30.2",
        "end_ip": "192.168.30.254"
    }

    #dhcp = cli.request("ADD_DHCP_SERVER", **message)
    #print 'dhcp["results"]["mkey"] = ', dhcp["results"]["mkey"]

    message = {
        "vdom": "osvdm21",
        "id": 1
    }
    #print cli.request("DELETE_DHCP_SERVER", **message)
    #print cli.request("GET_DHCP_SERVER", **message)

    #time.sleep(0)
    message = {
        "name": "osvdm20"
    }
    #print cli.request("ADD_VDOM", **message)
    #print cli.request("DELETE_VDOM", **message)
    #print cli.request("GET_VDOM", **message)
    #print cli.request("ADD_VDOM_LNK", **message)
    #print cli.request("GET_VDOM_LNK", **message)
    #sleep(5)
    #print cli.request("DELETE_VDOM_LNK", **message)
    #print cli.request("GET_VDOM_LNK", {"name": ""})
    message = {
        "id": 1,
        "vdom": "osvdm15",
        #"rid": 1,
        "reserved_address": """[
            {
                "id": 1,
                "ip": "192.168.30.200",
                "mac": "00:0C:29:70:51:D6"
            },
            {
                "id": 2,
                "ip": "192.168.30.201",
                "mac": "00:0C:29:70:51:D7"
            }
        ]"""
    }
    message1 = {
        "id": 1,
        "vdom": "osvdm15",
        "rid": 0,
        "ip": "192.168.30.201",
        "mac": "00:0C:29:70:52:D6"
    }
    #print cli.request("SET_DHCP_SERVER_RSV_ADDR", **message)
    message = {
        "vdom": "root"
    }
    #print cli.request("GET_ROUTER_STATIC", **message)
    message = {
        "vdom": "root",
        "dst": "10.160.37.0 255.255.255.0",
        "device": "port32",
        "gateway": "10.160.37.1"
    }
    #print cli.request("ADD_ROUTER_STATIC", **message)
    message = {
        "id": 4,
        "vdom": "root"
    }
    #print cli.request("DELETE_ROUTER_STATIC", **message)
    message = {
        "vdom": "root",
        "srcintf": "npu0_vlink0",
        "dstintf": "any",
        "poolname": "t1"
    }
    #print cli.request("ADD_FIREWALL_POLICY", **message)
    message = {
        "vdom": "osvdm1"
    }
    #res = cli.request("GET_FIREWALL_POLICY", **message)
    print "############################"
    #print "res['results']=%s" % res["results"]
    """
    if res["results"]:
        print "head id = %s" % res["results"][0]["policyid"]
    else:
        print "else"
    print "############################"
    """
    #print cli.request("DELETE_FIREWALL_POLICY", **message)
    message = {
        "vdom": "osvdm21",
        "name": "test",
        "extip": "169.254.254.2",
        "extintf": "vlan-ext1-4000",
        "mappedip": "192.168.11.3"
    }
    #print cli.request("ADD_FIREWALL_VIP", **message)
    message = {
        "vdom": "root",
        "name": "10.160.37.115"
    }
    #print cli.request("GET_FIREWALL_VIP", **message)
    #print cli.request("DELETE_FIREWALL_VIP", **message)
    message = {
        "name": "test3",
        "startip": "192.168.20.100",
        "comments": "abcdefg0123456789"
    }
    #print cli.request("ADD_FIREWALL_IPPOOL", **message)
    message = {
        "name": "test3",
        "vdom": "root"
    }
    #print cli.request("GET_FIREWALL_IPPOOL", **message)
    #print cli.request("DELETE_FIREWALL_IPPOOL", **message)
    message = {
        "vdom": "root"
    }
    #print cli.request("GET_FIREWALL_IPPOOL", **message)
    message = {
        "name": "test44",
        "vdom": "osvdm1",
        "subnet": "192.168.44.0 255.255.255.0"
    }
    #print cli.request("ADD_FIREWALL_ADDRESS", **message)
    message = {
        "name": "test33",
        "vdom": "osvdm1"
    }
    #print cli.request("GET_FIREWALL_ADDRESS", **message)
    message = {
        "name": "test33",
        "vdom": "osvdm1"
    }
    #print cli.request("DELETE_FIREWALL_ADDRESS", **message)

    message = {
        "name": "testgrp33",
        "vdom": "osvdm1",
        "members": ["test33"]
    }
    #print cli.request("ADD_FIREWALL_ADDRGRP", **message)
    message = {
        "name": "testgrp33",
        "vdom": "osvdm1"
    }
    #print cli.request("GET_FIREWALL_ADDRGRP", **message)
    message = {
        "name": "testgrp33",
        "vdom": "osvdm1",
        "members": ["test33", "test44"]
    }
    #print cli.request("SET_FIREWALL_ADDRGRP", **message)
    message = {
        "name": "testgrp33",
        "vdom": "osvdm1"
    }
    #print cli.request("GET_FIREWALL_ADDRGRP", **message)
    message = {
        "name": "testgrp33",
        "vdom": "osvdm1"
    }
    #print cli.request("DELETE_FIREWALL_ADDRGRP", **message)
    message = {
        "id": 2,
        "vdom": "osvdm1",
        "before": "1"
    }
    #print cli.request("MOVE_FIREWALL_POLICY", **message)
    cli.logout()
    print ""
