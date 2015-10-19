# Copyright 2015 Fortinet, Inc.
# All rights reserved.
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


"""Implentation of Fortinet ML2 Mechanism driver for ML2 Plugin."""

import netaddr
import json
import httplib
import sys
import os

from oslo.config import cfg

from neutron.openstack.common import importutils
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.db import models_v2

from neutron.db import api as db_api
from neutron.common import constants as l3_constants
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2 import db

from neutron.plugins.ml2.drivers.fortinet.db import models as fortinet_db
from neutron.plugins.ml2.drivers.fortinet.api_client import client
from neutron.plugins.ml2.drivers.fortinet.api_client import exception
from neutron.plugins.ml2.drivers.fortinet.common import constants as const
from neutron.plugins.ml2.drivers.fortinet.common import resources as resources
from neutron.plugins.ml2.drivers.fortinet.tasks import constants as t_consts
from neutron.plugins.ml2.drivers.fortinet.tasks import tasks

from neutron.agent import securitygroups_rpc
from neutron.common import constants
from neutron.extensions import portbindings
#from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent


LOG = logging.getLogger(__name__)

cfg.CONF.import_group("ml2_fortinet",
                      "neutron.plugins.ml2.drivers.fortinet.common.config")


class FortinetMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """ML2 Mechanism driver for Fortinet devices."""

    def __init__(self):
        sg_enabled = securitygroups_rpc.is_firewall_enabled()
        vif_details = {portbindings.CAP_PORT_FILTER: sg_enabled,
                       portbindings.OVS_HYBRID_PLUG: sg_enabled}
        super(FortinetMechanismDriver, self).__init__(
            constants.AGENT_TYPE_OVS,
            portbindings.VIF_TYPE_OVS,
            vif_details)

        self._driver = None
        self._fortigate = None
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()

    def check_segment_for_agent(self, segment, agent):
            mappings = agent['configurations'].get('bridge_mappings', {})
            tunnel_types = agent['configurations'].get('tunnel_types', [])
            LOG.debug(_("Checking segment: %(segment)s "
                        "for mappings: %(mappings)s "
                        "with tunnel_types: %(tunnel_types)s"),
                      {'segment': segment, 'mappings': mappings,
                       'tunnel_types': tunnel_types})
            network_type = segment[driver_api.NETWORK_TYPE]
            if network_type == 'local':
                return True
            elif network_type in tunnel_types:
                return True
            elif network_type in ['flat', 'vlan']:
                return segment[driver_api.PHYSICAL_NETWORK] in mappings
            else:
                return False


    def initialize(self):
        """Initilize of variables needed by this class."""
        self.Fortinet_init()

    def Fortinet_init(self):
        """Fortinet specific initialization for this class."""
        LOG.debug(_("FortinetMechanismDriver_init"))
        self._fortigate = {
            "address": cfg.CONF.ml2_fortinet.address,
            "username": cfg.CONF.ml2_fortinet.username,
            "password": cfg.CONF.ml2_fortinet.password,
            "int_interface": cfg.CONF.ml2_fortinet.int_interface,
            "ext_interface": cfg.CONF.ml2_fortinet.ext_interface,
            "tenant_network_type": cfg.CONF.ml2_fortinet.tenant_network_type,
            "vlink_vlan_id_range": cfg.CONF.ml2_fortinet.vlink_vlan_id_range,
            "vlink_ip_range": cfg.CONF.ml2_fortinet.vlink_ip_range,
            "vip_mappedip_range": cfg.CONF.ml2_fortinet.vip_mappedip_range
        }

        api_server = [(self._fortigate["address"], 80, False)]
        self._driver = client.FortiosApiClient(api_server,
            self._fortigate["username"], self._fortigate["password"])

        for key in const.FORTINET_PARAMS:
            self.sync_conf_to_db(key)

        session = db_api.get_session()
        cls = fortinet_db.Fortinet_Interface
        ext_inf = {
            "name": self._fortigate["ext_interface"],
            "vdom": const.EXT_VDOM
        }
        record = fortinet_db.query_record(session, cls, **ext_inf)
        if not record:
            fortinet_db.add_record(session, cls, **ext_inf)

            """create a vdom for external network if it doesn't exist"""
            try:
                message = {
                    "name": const.EXT_VDOM,
                }
                self._driver.request("GET_VDOM", **message)
            except exception.ResourceNotFound:
                LOG.info(_("external vdom doesn't exist, creating one"))
                self._driver.request("ADD_VDOM", **message)
                message = {
                           "name": self._fortigate["ext_interface"],
                           "vdom": const.EXT_VDOM
                }
                self._driver.request("SET_VLAN_INTERFACE", **message)

    def sync_conf_to_db(self, param):
        cls = getattr(fortinet_db, const.FORTINET_PARAMS[param]["cls"])
        conf_list = self.get_range(param)
        session = db_api.get_session()
        records = fortinet_db.query_records(cls, session)
        for record in records:
            for key in const.FORTINET_PARAMS[param]["keys"]:
                _element = const.FORTINET_PARAMS[param]["type"](record[key])
                if _element not in conf_list and not record.allocated:
                    kwargs.setdefault(key, record[key])
                    fortinet_db.delete_record(cls, session, **kwargs)
        try:
            for i in range(0, len(conf_list),
                           len(const.FORTINET_PARAMS[param]["keys"])):
                kwargs = {}
                for key in const.FORTINET_PARAMS[param]["keys"]:
                    kwargs.setdefault(key, str(conf_list[i]))
                    i += 1
                LOG.debug(_("######### adding kwargs = %s" % kwargs))
                fortinet_db.add_record(session, cls, **kwargs)
        except IndexError:
            LOG.error(_("The number of the configure range is not even,"
                        "the last one of %(param)s can not be used"),
                      {'param': param})
            raise IndexError


    def get_range(self, param):
        _type = const.FORTINET_PARAMS[param]["type"]
        if const.FORTINET_PARAMS[param]["format"]:
            min, max = self._fortigate[param].split(const.FIELD_DELIMITER)
            if _type(min) > _type(max):
                min, max = max, min
            if _type == int:
                min, max =_type(min), _type(max) + 1
            result = const.FORTINET_PARAMS[param]["range"](min, max)
        else:
            LOG.debug(_('const.FORTINET_PARAMS[param]=%s' % const.FORTINET_PARAMS[param]))
            result = const.FORTINET_PARAMS[param]["range"](
                                _type(self._fortigate[param]),
                                const.PREFIX["netmask"])
            LOG.debug(_("!!!!!!! result %s param_range = %s" % (param, result)))
        return result if isinstance(result, list) else list(result)

    @staticmethod
    def _getid(context):
        id = getattr(context, 'request_id', None)
        if not id:
            raise ValueError("not get request_id")
        return id

    def add_record(self, context, cls, **kwargs):
        res = cls.add_record(context, **kwargs)
        if res.get('rollback', {}):
            self.task_manager.add(self._getid(context), **res['rollback'])
        return res.get('result', None)

    """
    def query_record(self, cls, context, **kwargs):
        return fortinet_db.cls.query(context, **kwargs)

    def query_records(self, cls, context, **kwargs):
        return fortinet_db.cls.query(context, **kwargs)
    """

    def _rollback_on_err(self, context, e):
        resources.Exinfo(e)
        self.task_manager.update_status(self._getid(context),
                                        t_consts.TaskStatus.ROLLBACK)

    """
    def add_dev_cnf(self, context, cls, **kwargs):
        if isinstance(cls, type):
            cls = cls()
        res = cls.add(self._driver, kwargs)
    """

    @staticmethod
    def _getip(ipsubnet, place):
        return "%s %s" % (ipsubnet[place], ipsubnet.netmask)

    def op(self, context, func, **data):
        res = func(self._driver, data)
        if res.get('rollback', {}):
            self.task_manager.add(self._getid(context), **res['rollback'])
        return res.get('result', res)

    def create_network_precommit(self, mech_context):
        """Create Network in the mechanism specific database table."""
        LOG.debug(_("++++++++++create_network_precommit+++++++++++++++++++++"))
        network = mech_context.current
        context = mech_context._plugin_context
        tenant_id = network['tenant_id']
        LOG.debug(_("!!!!!!! mech_context.current = %s" % mech_context.current))
        LOG.debug(_("!!!!!!! context = %s" % context))
        if network["router:external"]:
            return
        # currently supports only one segment per network
        segment = mech_context.network_segments[0]
        network_type = segment['network_type']
        if network_type != 'vlan':
            raise Exception(_("Fortinet Mechanism: failed to create network, "
                              "only network type vlan is supported"))
        try:
            namespace = self.add_record(context,
                                        fortinet_db.Fortinet_ML2_Namespace,
                                        tenant_id=tenant_id)
            self.op(context, resources.Vdom.add, name=namespace.vdom)

            vlink_vlan = self.add_record(context,
                            fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                            vdom=namespace.vdom)

            vlink_ip = self.add_record(context,
                            fortinet_db.Fortinet_Vlink_IP_Allocation,
                            vdom=namespace.vdom, vlan_id=vlink_vlan.vlan_id)
            if vlink_ip:
                ipsubnet = netaddr.IPNetwork(vlink_ip.vlink_ip_subnet)
                try:

                    self.op(context, resources.VlanInterface.get,
                            name=vlink_vlan.inf_name_ext_vdom,
                            vdom=const.EXT_VDOM)
                except exception.ResourceNotFound:
                    self.op(context, resources.VlanInterface.add,
                            name=vlink_vlan.inf_name_ext_vdom,
                            vdom=const.EXT_VDOM,
                            vlanid=vlink_vlan.vlan_id,
                            interface="npu0_vlink0",
                            ip=self._getip(ipsubnet, 1))
                try:
                    self.op(context, resources.VlanInterface.get,
                            name=vlink_vlan.inf_name_int_vdom,
                            vdom=namespace.vdom)

                except exception.ResourceNotFound:
                    self.op(context, resources.VlanInterface.add,
                            name=vlink_vlan.inf_name_int_vdom,
                            vdom=namespace.vdom,
                            vlanid=vlink_vlan.vlan_id,
                            interface="npu0_vlink1",
                            ip=self._getip(ipsubnet, 2))

        except Exception as e:
            #self._rollback_on_err(context, e)
            raise e
        LOG.info(_("create network (precommit): "
                   "network type = %(network_type)s "
                   "for tenant %(tenant_id)s"),
                 {'network_type': network_type,
                  'tenant_id': tenant_id})


    def create_network_postcommit(self, mech_context):
        """Create Network as a portprofile on the switch."""
        LOG.debug(_("++++++++++create_network_postcommit+++++++++++++++++++++"))
        LOG.debug(_("create_network_postcommit: called"))
        network = mech_context.current
        LOG.debug(_("&&&&& mech_context.current = %s" % network))
        if network["router:external"]:
            # TODO
            return
        # use network_id to get the network attributes
        # ONLY depend on our db for getting back network attributes
        # this is so we can replay postcommit from db

        #network_id = network['id']

        network_name = network["name"]
        tenant_id = network['tenant_id']

        segments = mech_context.network_segments
        # currently supports only one segment per network
        segment = segments[0]
        #network_type = segment['network_type']
        vlan_id = segment['segmentation_id']
        context = mech_context._plugin_context
        namespace = fortinet_db.query_record(
            context, fortinet_db.Fortinet_ML2_Namespace, tenant_id=tenant_id)
        inf_name = const.PREFIX["inf"] + str(vlan_id)
        try:
            import ipdb; ipdb.set_trace()
            self.op(context, resources.VlanInterface.get,
                    name=inf_name, vdom=namespace.vdom)

        except exception.ResourceNotFound:
            self.op(context, resources.VlanInterface.add,
                    name=inf_name,
                    vdom=namespace.vdom,
                    vlanid=vlan_id,
                    interface=self._fortigate["int_interface"],
                    alias=network_name)

        except Exception as e:
            self._rollback_on_err(context, e)
            raise ml2_exc.MechanismDriverError(
                _("Fortinet Mechanism: create_network_postcommmit failed"))



    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""
        LOG.debug(_("delete_network_precommit: called"))

        network = mech_context.current
        network_id = network['id']
        context = mech_context._plugin_context
        ext_network = fortinet_db.get_ext_network(context, network_id)
        if ext_network:
            return

        tenant_id = network['tenant_id']
        vlan_id = network['provider:segmentation_id']
        try:
            message = {
                "name": const.PREFIX["inf"] + str(vlan_id)
            }
            self._driver.request("DELETE_VLAN_INTERFACE", **message)

        except Exception:
            LOG.exception(
                _("Fortinet Mechanism: failed to delete network in db"))
            raise Exception(
                _("Fortinet Mechanism: delete_network_precommit failed"))

        LOG.info(_("delete network (precommit): %(network_id)s"
                   " with vlan = %(vlan_id)s"
                   " for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})


    def delete_network_postcommit(self, mech_context):
        """Delete network which translates to remove vlan interface
        and related vdom from the fortigate.
        """
        LOG.debug(_("delete_network_postcommit: called"))
        network = mech_context.current
        network_id = network['id']
        context = mech_context._plugin_context
        ext_network = fortinet_db.get_ext_network(context, network_id)
        if ext_network:
            return
        tenant_id = network['tenant_id']
        if not fortinet_db.tenant_network_count(context, tenant_id):
            try:
                self.fortinet_delete_vlink(context, tenant_id)
                namespace = fortinet_db.get_namespace(context, tenant_id)
                message = {
                        "name": namespace.vdom,
                }
                self._driver.request("DELETE_VDOM", **message)
                fortinet_db.delete_namespace(context, tenant_id)
                LOG.info(_("delete network (postcommit): tenant %(tenant_id)s"
                       "vdom = %(vdom)s"),
                      {'tenant_id': tenant_id,
                       "vdom": namespace.vdom})
            except Exception:
                LOG.exception(_("Fortinet API client: failed to delete network"))
                raise Exception(
                    _("Fortinet switch exception, "
                      "delete_network_postcommit failed"))



    def update_network_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def update_network_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass


    def create_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("create_subnetwork_precommit: called"))


    def create_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("create_subnetwork_postcommit: called"))
        LOG.debug(_("%%%%%%   mech_context = %s" % mech_context))
        LOG.debug(_("%%%%%%   dir(mech_context) = %s" % dir(mech_context)))
        LOG.debug(_("%%%%%%   mech_context.current = %s" % mech_context.current))
        gateway = mech_context.current["gateway_ip"]
        network_id = mech_context.current["network_id"]
        subnet_id = mech_context.current["id"]
        tenant_id = mech_context.current["tenant_id"]
        context = mech_context._plugin_context
        ext_network = fortinet_db.get_ext_network(context, network_id)
        if ext_network:
            try:
                message = {
                    "vdom": const.EXT_VDOM,
                    "dst": const.EXT_DEF_DST,
                    "device": self._fortigate["ext_interface"],
                    "gateway": gateway
                }
                response = self._driver.request("ADD_ROUTER_STATIC", **message)
                LOG.debug(_("%%%%%%   response = %s" % response))
                mkey = response["results"]["mkey"]
                _test = fortinet_db.create_static_router(context,
                                                 subnet_id,
                                                 message["vdom"],
                                                 mkey)
                LOG.debug(_("$$$$$$ fortinet_db.create_static_router %s" % _test))
                LOG.debug(_("context %s, subnet_id %s, vdom %s, mkey %s" % (context, subnet_id, const.EXT_VDOM, mkey)))

            except Exception:
                LOG.exception(_("Fortinet API client: fail to "
                                "add the static router"))
                raise Exception(_("Fortinet API exception, "
                                  "delete_network_postcommit failed"))
        else:
            namespace = fortinet_db.get_namespace(context, tenant_id)
            vdom = namespace["vdom"]
            session = mech_context._plugin_context.session
            self._segments = db.get_network_segments(session, network_id)
            LOG.debug(_("  self._segments = %s" % self._segments))
            vlan_id = str(self._segments[0]["segmentation_id"])
            netmask = netaddr.IPNetwork(mech_context.current["cidr"]).netmask
            start_ip = mech_context.current["allocation_pools"][0]["start"]
            end_ip = mech_context.current["allocation_pools"][0]["end"]
            try:
                message = {
                    "vdom": vdom,
                    "interface": const.PREFIX["inf"] + vlan_id,
                    "gateway": gateway,
                    "netmask": netmask,
                    "start_ip": start_ip,
                    "end_ip": end_ip
                }
                response = self._driver.request("ADD_DHCP_SERVER", **message)
                LOG.debug(_("%%%%%%   response1 = %s" % response))
                mkey = response["results"]["mkey"]
                fortinet_db.create_subnet(context, subnet_id, mkey)

                update_inf = {
                    "name": const.PREFIX["inf"] + str(vlan_id),
                    "vdom": vdom,
                    "ip": gateway,
                    "netmask": netmask
                }
                response = self._driver.request("SET_VLAN_INTERFACE", **update_inf)
                LOG.debug(_("%%%%%%   response2 = %s" % response))
            except Exception:
                # TODO: need to send delete_dhcp_server to
                # fortigate in case of failed
                LOG.exception(_("Fortinet API client: failed to delete network"))
                raise Exception(_("Fortinet switch exception, "
                                  "delete_network_postcommit failed"))


    def delete_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("delete_subnetwork_precommit: called"))

    def delete_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("delete_subnetwork_postcommit: called"))
        LOG.debug(_("%%%%%% mech_context.current=%s" % mech_context.current))
        context = mech_context._plugin_context
        subnet_id = mech_context.current["id"]
        static_router = fortinet_db.get_static_router(context, subnet_id)
        LOG.debug(_("%%%%%% static_router=%s" % static_router))
        if static_router:
            try:
                message = {
                    "vdom": const.EXT_VDOM,
                    "id": static_router.edit_id
                }
                response = self._driver.request("DELETE_ROUTER_STATIC",
                                                **message)
                LOG.debug(_("%%%%%%   response = %s" % response))
                fortinet_db.delete_static_router(context,
                                                 subnet_id)
            except Exception:
                LOG.exception(_("Fortinet API client: fail to "
                                "delete the static router"))
                raise Exception(_("Fortinet API exception, "
                                  "delete_network_postcommit failed"))

        else:
            subnet = fortinet_db.get_subnet(context, subnet_id)
            if subnet:
                try:
                    message = {
                        "vdom": subnet.vdom,
                        "id": subnet.mkey
                    }
                    self._driver.request("DELETE_DHCP_SERVER", **message)
                    fortinet_db.delete_subnet(context, subnet_id)
                    if not fortinet_db.get_subnets(context, subnet.vdom):
                        message = {
                        "name": subnet.vdom
                        }
                        self._driver.request("DELETE_VDOM", **message)

                except Exception:
                    LOG.exception(_("Failed to delete subnet"))
                    raise Exception(_("delete_network_postcommit failed"))


    def update_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_subnet_precommit(self: called"))

    def update_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_subnet_postcommit: called"))

    def _update_reserved_ips(self, context, subnet_id):
        reserved_addresses = []
        reserved_ips = fortinet_db.get_reserved_ips(context, subnet_id)
        subnet = fortinet_db.get_subnet(context, subnet_id)
        dhcp_server_id = subnet.mkey
        vdom = subnet.vdom
        for reserved_ip in reserved_ips:
            reserved_address = {
                "id": reserved_ip.edit_id,
                "ip": reserved_ip.ip,
                "mac": reserved_ip.mac
            }
            reserved_addresses.append(reserved_address)
        _reserved_address = json.dumps(reserved_addresses)
        if subnet:
            message = {
                "id": dhcp_server_id,
                "vdom": vdom,
                "reserved_address": _reserved_address
            }
            self._driver.request("SET_DHCP_SERVER_RSV_ADDR", **message)

    def create_port_precommit(self, mech_context):
        """Create logical port on the switch (db update)."""
        LOG.debug(_("create_port_precommit: called"))
        #network = mech_context.current
        port = mech_context.current
        LOG.debug(_("!!!!! mech_context = %s" % mech_context))
        LOG.debug(_("!!!!! mech_context.current = %s" % port))
        LOG.debug(_("!!!!! mech_context.network.current = %s" % mech_context.network.current))
        context = mech_context._plugin_context
        tenant_id = port["tenant_id"]
        port_id = port["id"]
        subnet_id = port["fixed_ips"][0]["subnet_id"]
        ip_address = port["fixed_ips"][0]["ip_address"]
        mac = port["mac_address"]
        kwargs = {'id': subnet_id}
        session = context.session
        subnet = fortinet_db.get_record(session, models_v2.Subnet, **kwargs)
        LOG.debug(_("!!!!! subnet = %s" % subnet))
        LOG.debug(_("!!!!! port['device_owner'] = %s" % port["device_owner"]))
        if port["device_owner"] in ["network:router_gateway"]:
            if fortinet_db.get_ext_network(context, port["network_id"]):
                #add ippool and its related firewall policy
                self._set_ext_gw(context, port)

        elif port["device_owner"] in ['compute:nova']:
            # add dhcp related functions
            fortinet_db.create_reserved_ip(context, port_id, subnet_id,
                                       tenant_id, ip_address, mac)
            self._update_reserved_ips(context, subnet_id)

        elif port["device_owner"] in ['network:router_interface']:
            # add firewall address and address group
            vdom = fortinet_db.get_namespace(context, tenant_id).vdom
            if subnet.cidr:
                _net = netaddr.IPNetwork(subnet.cidr)
                addr = {
                    "vdom": vdom,
                    "name": "%s" % _net.network,
                    "subnet": "%s %s" % (_net.network, _net.netmask)
                }
                LOG.debug(_("##### addr = %s" % addr))
                self.add_address(context, **addr)

                addrgrp = {
                    "name": const.PREFIX['addrgrp'] + vdom,
                    "vdom": vdom,
                    "members": [addr['name'],]
                 }
                LOG.debug(_("##### addrgrp = %s" % addrgrp))
                self.add_member_addrgrp(context, **addrgrp)
                policy = {
                    "vdom": vdom,
                    "srcintf": "any",
                    "srcaddr": addrgrp['name'],
                    "dstintf": "any",
                    "dstaddr": addrgrp['name'],
                    "nat": "disable"
                }
                self._add_firewall_policy(context, **policy)
        else:
            # default nothing change
            pass
        return


    def create_port_postcommit(self, mech_context):
        """Associate the assigned MAC address to the portprofile."""
        LOG.debug(_("create_port_postcommit: called"))
        #network = mech_context.current
        port = mech_context.current
        LOG.debug(_("!!!!! mech_context = %s" % mech_context))
        LOG.debug(_("!!!!! mech_context.current = %s" % port))

    def delete_port_postcommit(self, mech_context):
        LOG.debug(_("delete_port_postcommit: called"))
        port = mech_context.current
        LOG.debug(_("!!!!! mech_context = %s" % mech_context))
        LOG.debug(_("!!!!! mech_context.current = %s" % port))
        context = mech_context._plugin_context
        port_id = port["id"]
        subnet_id = port["fixed_ips"][0]["subnet_id"]
        #ip_address = port["fixed_ips"][0]["ip_address"]
        #mac = port["mac_address"]
        vdom = fortinet_db.get_subnet(context, subnet_id).vdom
        kwargs = {'id': subnet_id}
        session = context.session
        subnet = fortinet_db.get_record(session, models_v2.Subnet, **kwargs)
        LOG.debug(_("!!!!! subnet = %s" % subnet))

        if port["device_owner"] in ["network:router_gateway"]:
            if fortinet_db.get_ext_network(context, port["network_id"]):
                #delete ippool and its related firewall policy
                self._clr_ext_gw(context, port)

        elif port["device_owner"] in ['compute:nova']:
            # delete dhcp related functions
            reserved_ip = fortinet_db.delete_reserved_ip(context, port_id)
            if reserved_ip:
                self._update_reserved_ips(context, reserved_ip.subnet_id)

        elif port["device_owner"] in ['network:router_interface']:
            # add firewall address and address group
            _net = netaddr.IPNetwork(subnet.cidr)
            addrgrp = {
                    "name": const.PREFIX['addrgrp'] + vdom,
                    "vdom": vdom,
                    "members": ["%s" % _net.network]
                 }
            LOG.debug(_("##### addrgrp = %s" % addrgrp))
            self.delete_member_addrgrp(context, **addrgrp)

            addr = {
                "vdom": vdom,
                "name": "%s" % _net.network
            }
            LOG.debug(_("##### addr = %s" % addr))
            self.delete_address(context, **addr)
        else:
            # default nothing change
            pass
        return


    def update_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_port_precommit"))
        port = mech_context.current
        LOG.debug(_("!!!!! mech_context = %s" % mech_context))
        LOG.debug(_("!!!!! mech_context.current = %s" % port))
        #super(FortinetMechanismDriver, self).\
        #    create_port_precommit(mech_context)

    def update_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_port_postcommit: called"))
        port = mech_context.current
        LOG.debug(_("!!!!! mech_context = %s" % mech_context))
        LOG.debug(_("!!!!! mech_context.current = %s" % port))
        #super(FortinetMechanismDriver, self).\
        #    create_port_postcommit(mech_context)

    def _update_record(self, context, param, **kwargs):
        LOG.debug(_("_update_record: called"))
        kws = {
                "vdom": kwargs["vdom"],
                "allocated": kwargs["allocated"]
        }
        cls = getattr(fortinet_db, const.FORTINET_PARAMS[param]["cls"])
        record = fortinet_db.query_record(context, cls, **kws)
        LOG.debug(_("!!!!@@!! record: %s" % record))
        if not record:
            kws = {"allocated": False}
            record = fortinet_db.query_record(context, cls, **kws)
            cls.update(context, record, **kwargs)
            LOG.debug(_("!!!!! context.session= %(context.session)s,"
                    "cls=%(cls)s, record=%(record)s",
                    {'context.session': context.session,
                     'cls': cls, 'record': record}))
            return record
        return None

    def add_namespace(self, context, tenant_id):
        try:
            namespace = fortinet_db.create_namespace(context, tenant_id)
            LOG.debug(_("!!!!!!! namespace = %s" % namespace))
            message = {
                "name": namespace["vdom"]
            }
            LOG.debug(_("message = %s"), message)
            self._driver.request("ADD_VDOM", **message)
            return namespace
        except Exception:
            LOG.exception(_("Fortinet Mechanism: failed to add_namespace"))
            self._driver.request("DELETE_VDOM", **message)
            fortinet_db.delete_namespace(context, tenant_id)
            raise Exception(_("Fortinet Mechanism: add_namespace failed"))


    def delete_namespace(self, context, tenant_id):
        try:
            namespace = fortinet_db.get_namespace(context, tenant_id)
            if not namespace:
                LOG.debug(_("There is not any record with the tenant id"))
                return None
            LOG.debug(_("!!!!!!! namespace = %s" % namespace))
            message = {
                "name": namespace["vdom"]
            }
            LOG.debug(_("message = %s"), message)
            self._driver.request("DELETE_VDOM", **message)
            fortinet_db.delete_namespace(context, tenant_id)
        except Exception:
            LOG.exception(_("Fortinet Mechanism: failed to delete_namespace"))
            raise Exception(_("Fortinet Mechanism: delete_namespace failed"))



    def _set_ext_gw(self, context, port):
        """
        :param context:
        :param port: example format
         port = {
            'status': 'DOWN',
            'binding:host_id': '',
            'allowed_address_pairs': [],
            'device_owner': 'network:router_gateway',
            'binding:profile': {},
            'fixed_ips': [{
                'subnet_id': u'09855a84-edfd-474d-b641-38a2bc63466a',
                'ip_address': u'10.160.37.111'
            }],
            'id': '6e68efc0-c0ca-40a2-a502-c2bf19304317',
            'security_groups': [],
            'device_id': u'8312d7a2-cae5-4e87-9c04-782c4a34bb8c',
            'name': '',
            'admin_state_up': True,
            'network_id': u'95eb736c-dd3b-4bf5-940a-8fa8e707a376',
            'tenant_id': '',
            'binding:vif_details': {},
            'binding:vnic_type': 'normal',
            'binding:vif_type': 'unbound',
            'mac_address': 'fa:16:3e:95:02:ab'
        }
        :return:
        """
        session = context.session
        kwargs = {}
        router = fortinet_db.get_router(context, port["device_id"])
        tenant_id = router.get("tenant_id", None)
        if not tenant_id:
            raise ValueError
        namespace = fortinet_db.get_namespace(context, tenant_id)
        LOG.debug(_("!!!!! namespace = %s" % namespace))
        if not namespace:
            namespace = self.add_namespace(context, tenant_id)
        kwargs["vdom"] = namespace.vdom
        LOG.debug(_("##### kwargs = %s" % kwargs))
        LOG.debug(_("##### port = %s" % port))
        cls = fortinet_db.Fortinet_Vlink_Vlan_Allocation
        vlink = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("##### vlink = %s" % vlink))

        if not vlink:
            self.fortinet_add_vlink(context, tenant_id)
            vlink = fortinet_db.get_record(session, cls, **kwargs)
            LOG.debug(_("##### vlink = %s" % vlink))
        ip_address = port["fixed_ips"][0]["ip_address"]
        try:
            self._add_ippool(ip_address)
            kwargs = {
                "vdom": const.EXT_VDOM,
                "srcintf": vlink.inf_name_ext_vdom,
                "dstintf": self._fortigate["ext_interface"],
                "poolname": ip_address
            }
            self._add_firewall_policy(context, **kwargs)

            netmask = self._get_subnet_netmask(context,
                                port["fixed_ips"][0]["subnet_id"])
                # add subip
            kwargs = {
                "name": self._fortigate["ext_interface"],
                "vdom": const.EXT_VDOM,
                "ip": ip_address,
                "netmask": str(netmask)
            }
            LOG.debug(_("#### kwargs=%s" % kwargs))
            if self._is_null_ip(context, kwargs["name"]):
                self._add_interface_subip(context, **kwargs)
            else:
                self._add_interface_ip(context, **kwargs)

        except Exception:
            LOG.error(_("set_ext_gw failed"))
            kwargs = {
               "vdom": const.EXT_VDOM,
               "poolname": ip_address
            }
            self._delete_firewall_policy(context, **kwargs)
            self._delete_ippool(ip_address)
            raise Exception


    def add_address(self, context, **kwargs):
        """
        :param context:
        :param kwargs: example
        {
            "vdom": "osvdm1",
            "name": "192.168.33.0",
            "subnet": "192.168.33.0 255.255.255.0"
        }
        :return:
        """
        LOG.debug(_("### add_address"))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Address
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### record = %s" % record))
        LOG.debug(_("### kwargs = %s" % kwargs))
        if not record:
            try:
                if kwargs.has_key("vdom"):
                    kwargs.setdefault("vdom", kwargs["vdom"])
                    del kwargs["vdom"]
                self._driver.request("ADD_FIREWALL_ADDRESS", **kwargs)

                if kwargs.has_key("vdom"):
                    kwargs.setdefault("vdom", kwargs["vdom"])
                    del kwargs["vdom"]
                record = fortinet_db.add_record(session, cls, **kwargs)
                LOG.debug(_("### record = %s" % record))
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("### Exception= %s" % Exception))
                    self._driver.request("DELETE_FIREWALL_ADDRESS", **kwargs)
                    fortinet_db.delete_record(session, cls, **kwargs)


    def delete_address(self, context, **kwargs):
        LOG.debug(_("### delete_address"))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Address
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### record = %s" % record))
        if not record:
            return None
        try:
            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom", kwargs["vdom"])
                del kwargs["vdom"]
            self._driver.request("DELETE_FIREWALL_ADDRESS", **kwargs)

            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom", kwargs["vdom"])
                del kwargs["vdom"]
            fortinet_db.delete_record(session, cls, **kwargs)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("### Exception= %s" % Exception))

    def add_addrgrp(self, context, **kwargs):
        """
        :param context:
        :param kwargs:
         {
            "name": "addrgrp_osvdm1",
            "vdom": "osvdm1",
            "members": ["192.168.33.0"]
         }
        :return:
        """
        LOG.debug(_("### add_addrgrp, kwargs=%s" % kwargs))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Address
        if not kwargs.get("members", None):
            LOG.debug(_("### there is no member"))
            return
        #record = fortinet_db.get_record(session, cls, **kwargs)
        #LOG.debug(_("### record = %s" % record))
        try:
            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom", kwargs["vdom"])
                del kwargs["vdom"]
            self._driver.request("ADD_FIREWALL_ADDRGRP", **kwargs)
            for name in kwargs["members"]:
                addrinfo = {
                    "name": name,
                    "vdom": kwargs["vdom"]
                }
                record = fortinet_db.get_record(session, cls, **addrinfo)
                LOG.debug(_("### record=%s" % record))
                if not record.group:
                    addrinfo.setdefault("group", kwargs["name"])
                    LOG.debug(_("### addrinfo=%s" % addrinfo))
                    fortinet_db.update_record(context, record, **addrinfo)
                else:
                    LOG.debug(_("### The memeber %(member)s "
                                "is already joined a group"),
                              {"member": record})
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("### Exception= %s" % Exception))


    def add_member_addrgrp(self, context, **kwargs):
        """
        :param context: for database
        :param kwargs:
            example format
            {
                "name": "osvdm1_net",
                "vdom": "osvdm1",
                "members": ["192.168.10.0", "192.168.33.0"]
            }
            each member of members is the address name to be added in
            the specific firewall address group in FGT.
        """
        LOG.debug(_("### add_member_addrgrp"))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Address
        if not kwargs.get("members", None) and not kwargs.get("name", None):
            LOG.debug(_("### there is no member and no group name"))
            return
        records = fortinet_db.get_records(session, cls, group=kwargs["name"])
        LOG.debug(_("### records = %s" % records))
        if not records:
            self.add_addrgrp(context, **kwargs)
        else:
            try:
                for name in kwargs["members"]:
                    addrinfo = {
                        "name": name,
                        "vdom": kwargs["vdom"]
                    }
                    record = fortinet_db.get_record(session, cls, **addrinfo)
                    if not record.group:
                        addrinfo.setdefault("group", kwargs["name"])
                        fortinet_db.update_record(context, record, **addrinfo)
                    else:
                        LOG.debug(_("### The memeber %(member)s "
                                    "is already joined a group"),
                                  {"member": record})
                for record in records:
                    kwargs["members"].append(record.name)
                if kwargs.has_key("vdom"):
                    kwargs.setdefault("vdom", kwargs["vdom"])
                    del kwargs["vdom"]
                self._driver.request("SET_FIREWALL_ADDRGRP", **kwargs)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("### Exception= %s" % Exception))


    def delete_member_addrgrp(self, context, **kwargs):
        """
        :param context: for database
        :param kwargs:
            example format
            {
                "name": "osvdm1_net",
                "vdom": "osvdm1",
                "members": ["192.168.10.0", "192.168.33.0"]
            }
            each member of members is the address name to be deleted in
            the specific firewall address group in FGT.
        """
        LOG.debug(_("### delete_member_addrgrp, kwargs=%s" % kwargs))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Address
        if not kwargs.get("members", None) and not kwargs.get("name", None):
            LOG.debug(_("### there is no member and no group name"))
            return
        records = fortinet_db.get_records(session, cls, group=kwargs["name"])
        LOG.debug(_("### records = %s" % records))
        if not records:
            LOG.error(_("There is not any record in db"))
            raise

        try:
            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom", kwargs["vdom"])
                del kwargs["vdom"]
            members = []
            for record in records:
                if record.name in kwargs["members"]:
                    fortinet_db.update_record(context, record, group=None)
                else:
                    members.append(record.name)
            if members:
                LOG.debug(_("### The member %(member)s "
                        "is kept in the group"),
                        {"member": members})
                kwargs["members"] = members
                self._driver.request("SET_FIREWALL_ADDRGRP", **kwargs)
            else:
                policy = {
                    "vdom": kwargs['vdom'],
                    "srcintf": "any",
                    "srcaddr": kwargs['name'],
                    "dstintf": "any",
                    "dstaddr": kwargs['name'],
                    "nat": "disable"
                }
                self._delete_firewall_policy(context, **policy)
                del kwargs["members"]
                self._driver.request("DELETE_FIREWALL_ADDRGRP", **kwargs)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("### Exception= %s" % Exception))


    @staticmethod
    def _get_subnet_netmask(context, subnet_id):
        session = context.session
        cls = models_v2.Subnet
        record = fortinet_db.get_record(session, cls, id=subnet_id)
        if record:
            return netaddr.IPNetwork(record.cidr).netmask
        else:
            LOG.error(("cannot find the subnet id %(id)s"), {"id": subnet_id})
            raise ValueError

    @staticmethod
    def _is_null_ip(context, interface):
        session = context.session
        cls = fortinet_db.Fortinet_Interface
        record = fortinet_db.get_record(session, cls, name=interface)
        if record:
            if const.EXT_DEF_DST in record.ip:
                return None
            else:
                return record.ip
        else:
            LOG.error(("cannot find the subnet id %(id)s"), {"id": subnet_id})
            raise ValueError


    def _clr_ext_gw(self, context, port):
        LOG.debug(_("##### port = %s" % port))
        session = context.session
        ip_address = port["fixed_ips"][0]["ip_address"]
        kwargs = {
            "vdom": const.EXT_VDOM,
            "poolname": ip_address
        }
        try:
            self._delete_firewall_policy(context, **kwargs)
            self._delete_ippool(ip_address)
            netmask = self._get_subnet_netmask(context,
                                port["fixed_ips"][0]["subnet_id"])
            kwargs = {
                "name": self._fortigate["ext_interface"],
                "vdom": const.EXT_VDOM
            }
            ip = "%s %s" % (ip_address, netmask)
            cls = fortinet_db.Fortinet_Interface
            record = fortinet_db.get_record(session, cls, **kwargs)
            kwargs.setdefault("ip", ip)
            if ip == record.ip:
                self._delete_interface_ip(context, **kwargs)
            else:
                self._delete_interface_subip(context, **kwargs)
        except Exception:
            LOG.error(_("clr_ext_gw failed"))
            raise Exception


    def _add_interface_ip(self, context, **kwargs):
        """
        :param context:
        :param kwargs: example format
            {
                "name": "port37",
                "vdom": "osvdm1",
                "ip": "10.160.37.110 255.255.255.0"
            }
        :return:
        """
        LOG.debug(_("#### _add_interface_ip %s" % kwargs))
        session = context.session
        update_inf = kwargs.copy()
        update_inf.setdefault("vdom", update_inf["vdom"])
        del update_inf["vdom"]
        cls = fortinet_db.Fortinet_Interface
        del kwargs["ip"]
        del kwargs["netmask"]
        LOG.debug(_("#### ############################################# %s" % kwargs))
        interface = fortinet_db.get_record(session, cls, **kwargs)
        if const.EXT_DEF_DST == getattr(interface, "ip"):
            try:
                res = self._driver.request("SET_VLAN_INTERFACE", **update_inf)
                if 200 == res["http_status"]:
                    if update_inf.has_key("vdom"):
                        update_inf.setdefault("vdom", update_inf["vdom"])
                        del update_inf["vdom"]
                    fortinet_db.update_record(context, interface, **update_inf)
            except Exception:
                LOG.exception(_("Failed to add interface address"))
                update_inf = {
                    "name": kwargs["name"],
                    "vdom": kwargs["vdom"],
                    "ip": const.EXT_DEF_DST
                }
                self._driver.request("SET_VLAN_INTERFACE", **update_inf)
                raise Exception


    def _delete_interface_ip(self, context, **kwargs):
        """
        :param context:
        :param kwargs: example format as below
            {
                "name": "port37",
                "ip": "10.160.37.20 255.255.255.0",
                "vdom": "root"
            }
        :return:
        """
        LOG.debug(_("#### _delete_interface_ip %s" % kwargs))
        session = context.session
        cls = fortinet_db.Fortinet_Interface
        interface = fortinet_db.get_record(session, cls, **kwargs)
        subips = fortinet_db.get_interface_subips(context, interface["name"])
        try:
            if subips:
                new_ip = subips.pop()
                update_inf = {
                    "name": interface["name"],
                    "vdom": interface["vdom"],
                    "secondaryips": subips
                }
                self._driver.request("SET_VLAN_INTERFACE", **update_inf)
                cls = fortinet_db.Fortinet_Interface_subip
                record = {
                    "ip": new_ip,
                    "interface": interface["name"],
                    "vdom": interface["vdom"]
                }
                fortinet_db.delete_record(session, cls, **record)
                del update_inf["secondaryips"]
                update_inf.setdefault("ip", new_ip)
            else:
                update_inf = {
                    "name": interface["name"],
                    "vdom": interface["vdom"],
                    "ip": const.EXT_DEF_DST
                }

            res = self._driver.request("SET_VLAN_INTERFACE", **update_inf)
            if 200 == res["http_status"]:
                del update_inf["vdom"]
                fortinet_db.update_record(context, interface, **update_inf)
        except Exception:
            LOG.exception(_("Failed to delete interface ip address"))
            raise Exception


    def _add_interface_subip(self, context, **kwargs):
        """
        :param context:
        :param kwargs: example format as below
            {
                "ip": "10.160.37.20 255.255.255.0",
                "interface": "port37",
                "vdom": "root"
            }
        :return:
        """
        LOG.debug(_("#### _add_interface_subip %s" % kwargs))
        session = context.session
        try:
            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom", kwargs["vdom"])
                del kwargs["vdom"]
            org_subips = fortinet_db.get_interface_subips(context,
                                                          kwargs["name"])
            org_subips.append(kwargs["ip"])
            update_inf = {
                "name": kwargs["name"],
                "vdom": kwargs["vdom"],
                "secondaryips": org_subips,
                "netmask": kwargs["netmask"]
            }
            LOG.debug(_("#### update_inf=%s" % update_inf))
            res = self._driver.request("SET_VLAN_INTERFACE", **update_inf)
            if 200 == res["http_status"]:
                update_inf = {
                    "ip": kwargs["ip"],
                    "vdom": kwargs["vdom"],
                    "name": kwargs["name"]
                }
                cls = fortinet_db.Fortinet_Interface_subip
                fortinet_db.add_record(session, cls, **update_inf)
        except Exception:
            LOG.exception(_("Failed to add interface sub ip"))
            org_subips = fortinet_db.get_interface_subips(context,
                                                          kwargs["name"])
            update_inf = {
                "name": kwargs["name"],
                "vdom": kwargs["vdom"],
                "secondaryips": org_subips
            }
            self._driver.request("SET_VLAN_INTERFACE", **update_inf)
            raise Exception


    def _delete_interface_subip(self, context, **kwargs):
        """
        :param context:
        :param kwargs: example format as below
            {
                "ip": "10.160.37.20 255.255.255.0",
                "name": "port37",
                "vdom": "root"
            }
        :return:
        """
        LOG.debug(_("#### _delete_interface_subip %s" % kwargs))
        session = context.session
        try:
            org_subips = fortinet_db.get_interface_subips(context,
                                                      kwargs["name"])
            if kwargs["ip"] not in org_subips:
                LOG.debug(_("Cannot find the ip %(ip)s in db"),
                              {"ip": kwargs["ip"]})
                return
            LOG.debug(_("#### org_subips=%s" % org_subips))
            org_subips.remove(kwargs["ip"])
            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom", kwargs["vdom"])
                del kwargs["vdom"]
            LOG.debug(_("#### org_subips=%s" % org_subips))
            update_inf = {
                "name": kwargs["name"],
                "vdom": kwargs["vdom"],
                "secondaryips": org_subips
            }
            LOG.debug(_("#### update_inf=%s" % update_inf))
            res = self._driver.request("SET_VLAN_INTERFACE", **update_inf)
            if 200 == res["http_status"]:
                cls = fortinet_db.Fortinet_Interface_subip
                fortinet_db.delete_record(session, cls, **kwargs)
        except Exception:
            LOG.exception(_("Failed to delete interface sub ip"))
            raise Exception


    def _add_firewall_policy(self, context, **kwargs):
        session = context.session
        LOG.debug(_("### enter: kwargs= %s" % kwargs))
        record = fortinet_db.get_record(session,
                                        fortinet_db.Fortinet_Firewall_Policy,
                                        **kwargs)
        LOG.debug(_("### enter: record= %s" % record))
        if not record:
            try:
                record = fortinet_db.add_record(session,
                                   fortinet_db.Fortinet_Firewall_Policy,
                                   **kwargs)
                LOG.debug(_("### enter: record= %s" % record))
                message = kwargs
                message["vdom"] = message.get("vdom", const.EXT_VDOM)
                message.pop("vdom", None)
                resp = self._driver.request("ADD_FIREWALL_POLICY", **message)
                kwargs["edit_id"] = resp["results"]["mkey"]
                LOG.debug(_("### kwargs= %s" % kwargs))
                fortinet_db.update_record(context, record, **kwargs)

            except Exception:
                LOG.error(_("### Exception= %s" % Exception))
                del_msg = {"vdom": message["vdom"], "id": message["edit_id"]}
                self._driver.request("DELETE_FIREWALL_POLICY", **del_msg)
                kwargs = {"id": record.id}
                fortinet_db.delete_record(session,
                               fortinet_db.Fortinet_Firewall_Policy,
                               **kwargs)
                raise Exception


    def _delete_firewall_policy(self, context, **kwargs):
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Policy
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### delete_firewall_policy record=%s" % record))
        if record:
            try:
                if record.edit_id:
                    message = {"vdom": record.vdom, "id": record.edit_id}
                    resp = self._driver.request("DELETE_FIREWALL_POLICY",
                                                **message)
                    LOG.debug(_("### resp=%s" % resp))
                    if httplib.OK == resp["http_status"]:
                        kwargs = {"id": record.id}
                        LOG.debug(_("### kwargs=%s" % kwargs))
                        fortinet_db.delete_record(session, cls, **kwargs)
            except Exception:
                LOG.error(_("Failed to delete firewall policy "
                                "interface. vdom=%(vdom)s, "
                                "id=%(id)s") %
                           ({"vdom": vdom, "id": record.edit_id}))
                raise Exception


    def fortinet_add_vlink(self, context, tenant_id):
        #cls = fortinet_db.Fortinet_ML2_Namespace
        _namespace = fortinet_db.query_record(context,
                fortinet_db.Fortinet_ML2_Namespace, tenant_id=tenant_id)

        LOG.debug(_("!!!!! vdom = %s" % vdom))
        vlink_vlan = {
            "vdom": vdom,
            "allocated": True
        }
        LOG.debug(_("!!!!! vlink_vlan = %s" % vlink_vlan))
        vlink_vlan_allocation = self._update_record(context,
                                                    "vlink_vlan_id_range",
                                                    **vlink_vlan)
        LOG.debug(_("!!!!! vlink_vlan_allocation = %s" % vlink_vlan_allocation))
        if vlink_vlan_allocation:
            vlink_vlan_allocation.inf_name_int_vdom = const.PREFIX["vint"] + \
                                       str(vlink_vlan_allocation.vlan_id)
            vlink_vlan_allocation.inf_name_ext_vdom = const.PREFIX["vext"] + \
                                       str(vlink_vlan_allocation.vlan_id)
            fortinet_db.update_record(context, vlink_vlan_allocation)
            vlink_ip = {
                "vdom": vdom,
                "vlan_id": vlink_vlan_allocation.vlan_id,
                "allocated": True
            }
            LOG.debug(_("!!!!! vlink_vlan_allocation = %s" % vlink_vlan_allocation))
            vlink_ip_allocation = self._update_record(context,
                                                      "vlink_ip_range",
                                                      **vlink_ip)
            LOG.debug(_("!!!!! vlink_ip_allocation = %s" % vlink_ip_allocation))
            if vlink_ip_allocation:
                try:
                    ipsubnet = netaddr.IPNetwork(
                        vlink_ip_allocation.vlink_ip_subnet)
                    message = {
                        "name": vlink_vlan_allocation.inf_name_ext_vdom,
                        "vdom": const.EXT_VDOM
                    }
                    response = self._driver.request("GET_VLAN_INTERFACE", **message)
                    if 200 == response["http_status"]:
                        LOG.debug(_("!!!!! response = %s" % response))
                except exception.ResourceNotFound:
                    message = {
                        "name": vlink_vlan_allocation.inf_name_ext_vdom,
                        "vlanid": vlink_vlan_allocation.vlan_id,
                        "vdom": const.EXT_VDOM,
                        "interface": "npu0_vlink0",
                        "ip": "%s %s" % (ipsubnet[1], ipsubnet.netmask)
                    }
                    self._driver.request("ADD_VLAN_INTERFACE", **message)
                except:
                    message = {
                        "name": vlink_vlan_allocation.inf_name_ext_vdom,
                        "vdom": const.EXT_VDOM
                    }
                    self._driver.request("DELETE_VLAN_INTERFACE", **message)
                    raise Exception(_(sys.exc_info()[0]))

                try:
                    message = {
                        "name": vlink_vlan_allocation.inf_name_int_vdom,
                        "vdom": vdom
                    }
                    response = self._driver.request("GET_VLAN_INTERFACE", **message)
                    if 200 == response["http_status"]:
                        LOG.debug(_("!!!!! response = %s" % response))
                except exception.ResourceNotFound:
                    message = {
                        "name": vlink_vlan_allocation.inf_name_int_vdom,
                        "vlanid": vlink_vlan_allocation.vlan_id,
                        "vdom": vdom,
                        "interface": "npu0_vlink1",
                        "ip": "%s %s" % (ipsubnet[2], ipsubnet.netmask)
                    }
                    self._driver.request("ADD_VLAN_INTERFACE", **message)
                    message = {
                        "vdom": vdom,
                        "dst": "0.0.0.0 0.0.0.0",
                        "device": vlink_vlan_allocation.inf_name_int_vdom,
                        "gateway": "0.0.0.0"
                    }
                    self._driver.request("ADD_ROUTER_STATIC", **message)
                except Exception as e:
                    import traceback, os.path
                    top = traceback.extract_stack()[-1]
                    LOG.error(_("#####################################"))
                    LOG.error(_(', '.join([type(e).__name__, os.path.basename(top[0]), str(top[1])])))
                    LOG.error(_("#####################################"))
                    self.fortinet_reset_vlink(context,
                                              vlink_vlan_allocation,
                                              vlink_ip_allocation)
                    LOG.error(_("Failed to add vlink"))
                    raise Exception(_(sys.exc_info()[0]))
                return True
        return False


    def fortinet_delete_vlink(self, context, tenant_id):
        session = context.session
        vdom = fortinet_db.get_namespace(context, tenant_id)
        vlink_vlan = {
            "vdom": vdom,
            "allocated": True
        }
        vlink_vlan_allocation = fortinet_db.get_record(session,
                                    fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                                    **vlink_vlan)
        if not vlink_vlan_allocation:
            return False
        vlink_ip = {
            "vdom": vdom,
            "vlan_id": vlink_vlan_allocation.vlanid,
            "allocated": True
        }
        vlink_ip_allocation = fortinet_db.get_record(session,
                                  fortinet_db.Fortinet_Vlink_IP_Allocation,
                                  **vlink_ip)
        if not vlink_ip_allocation:
            return False
        try:
            message = {
                "name": vlink_vlan_allocation.inf_name_ext_vdom
            }
            self._driver.request("DELETE_VLAN_INTERFACE", **message)
            message = {
                "name": vlink_vlan_allocation.inf_name_int_vdom
            }
            self._driver.request("DELETE_VLAN_INTERFACE", **message)
            self.fortinet_reset_vlink(context,
                                 vlink_vlan_allocation,
                                 vlink_ip_allocation)
        except:
            LOG.error(_("Failed to delete vlink"))
            raise Exception(_("Failed to delete vlink"))
        return True

    @staticmethod
    def fortinet_reset_vlink(context, vlink_vlan_allocation,
                             vlink_ip_allocation):
        vlink_vlan = {
            "vdom": None,
            "inf_name_int_vdom": None,
            "inf_name_ext_vdom": None,
            "allocated": False
        }
        if vlink_vlan_allocation:
            fortinet_db.update_record(context, vlink_vlan_allocation,
                                      **vlink_vlan)
        vlink_ip = {
            "vdom": None,
            "vlan_id": None,
            "allocated": False
        }
        if vlink_ip_allocation:
            fortinet_db.update_record(context, vlink_ip_allocation,
                                      **vlink_ip)


    def _add_ippool(self, ip):
        message = {
            "vdom": const.EXT_VDOM,
            "name": ip,
            "startip": ip
        }
        return self._driver.request("ADD_FIREWALL_IPPOOL", **message)


    def _delete_ippool(self, ip):
        message = {"vdom": const.EXT_VDOM}
        try:
            resp = self._driver.request("GET_FIREWALL_IPPOOL", **message)
            if 200 == resp["http_status"] and resp["results"]:
                ippools = [record["name"] for record in resp["results"]]
                LOG.debug(_("####ippools=%s, ip=%s" % (ippools, ip)))
                if ip in ippools:
                    message.setdefault("name", ip)
                    self._driver.request("DELETE_FIREWALL_IPPOOL", **message)
        except Exception:
            LOG.error(_("Cannot found the ippool %s" % message))
            raise NameError


    def bind_port(self, context):
        """Marks ports as bound.

        Binds external ports and ports.
        Fabric configuration will occur on the subsequent port update.
        Currently only vlan segments are supported.
        """
        LOG.debug(_("bind_port() called"))
        LOG.debug(_("####context=%s" % context))
        LOG.debug(_("####context.current=%s" % context.current))
        LOG.debug(_("####context.network.network_segments=%s" % context.network.network_segments))

        if context.current['device_owner'] == \
                l3_constants.DEVICE_OWNER_ROUTER_INTF:
            # check controller to see if the port exists
            # so this driver can be run in parallel with others that add
            # support for external port bindings
            for segment in context.network.network_segments:
                if segment[api.NETWORK_TYPE] == p_const.TYPE_VLAN:
                    context.set_binding(
                        segment[api.ID], portbindings.VIF_TYPE_OVS,
                        {portbindings.CAP_PORT_FILTER: False,
                         portbindings.OVS_HYBRID_PLUG: False})
                    return

        for segment in context.network.network_segments:
            if segment[api.NETWORK_TYPE] == p_const.TYPE_VLAN:
                context.set_binding(
                    segment[api.ID], portbindings.VIF_TYPE_OVS,
                    {portbindings.CAP_PORT_FILTER: False,
                    portbindings.OVS_HYBRID_PLUG: False})
