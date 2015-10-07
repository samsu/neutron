# Copyright 2015 Fortinet Inc.
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
#


"""Implentation of FortiOS service Plugin."""

import netaddr
import httplib

from oslo.config import cfg

from neutron.common import constants as l3_constants
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging

from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import models as ml2_db
from neutron.plugins.ml2.drivers.fortinet.db import models as fortinet_db
from neutron.plugins.ml2.drivers.fortinet.api_client import client
from neutron.plugins.ml2.drivers.fortinet.common import constants as const
from neutron.services.l3_router import l3_router_plugin as router

# TODO: the folowing two imports just for testing purpose
# TODO: need to be deleted later
from neutron.db import api as db_api
from neutron.db import models_v2

DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP


cfg.CONF.import_group("ml2_fortinet",
                      "neutron.plugins.ml2.drivers.fortinet.common.config")

LOG = logging.getLogger(__name__)


class FortinetL3ServicePlugin(router.L3RouterPlugin):
    """Fortinet L3 service Plugin."""

    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        """Initialize Fortinet L3 service Plugin"""
        super(FortinetL3ServicePlugin, self).__init__()
        self._fortigate = None
        self._driver = None
        self.Fortinet_init()

    def Fortinet_init(self):
        """Fortinet specific initialization for this class."""
        LOG.debug(_("FortinetL3ServicePlugin_init"))
        self._fortigate = {
            "address": cfg.CONF.ml2_fortinet.address,
            "username": cfg.CONF.ml2_fortinet.username,
            "password": cfg.CONF.ml2_fortinet.password,
            "int_interface": cfg.CONF.ml2_fortinet.int_interface,
            "ext_interface": cfg.CONF.ml2_fortinet.ext_interface,
            "tenant_network_type": cfg.CONF.ml2_fortinet.tenant_network_type,
            "vlink_vlan_id_range": cfg.CONF.ml2_fortinet.vlink_vlan_id_range,
            "vlink_ip_range": cfg.CONF.ml2_fortinet.vlink_ip_range
        }
        LOG.debug(_("!!!!!!! self._fortigate = %s" % self._fortigate))

        api_server = [(self._fortigate["address"], 80, False)]
        msg = {
            "username": self._fortigate["username"],
            "secretkey": self._fortigate["password"]
        }
        self._driver = client.FortiosApiClient(api_server,
                                               msg["username"],
                                               msg["secretkey"])

    def update_router(self, context, id, router):
        LOG.debug(_("######## update_router"))
        LOG.debug(_("######## context=%s" % context))
        LOG.debug(_("######## id=%s" % id))
        LOG.debug(_("######## router=%s" % router))
        return super(FortinetL3ServicePlugin, self).\
            update_router(context, id, router)


    def add_router_interface(self, context, router_id, interface_info):
        """creates vlnk on the fortinet device."""
        LOG.debug("FortinetL3ServicePlugin.add_router_interface: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        with context.session.begin(subtransactions=True):
            info = super(FortinetL3ServicePlugin, self).add_router_interface(
                context, router_id, interface_info)
            port = db.get_port(context.session, info["port_id"])
            port['admin_state_up'] = True
            port['port'] = port
            LOG.debug("FortinetL3ServicePlugin: "
                  "context=%(context)s"
                  "port=%(port)s "
                  "info=%(info)r",
                  {'context': context, 'port': port, 'info': info})

            #self._core_plugin.update_port(context, info["port_id"], port)

            interface_info = info
            subnet = self._core_plugin._get_subnet(context,
                                                   interface_info["subnet_id"])
            network_id = subnet['network_id']
            tenant_id = port["tenant_id"]
            port_filters = {'network_id': [network_id],
                            'device_owner': [DEVICE_OWNER_ROUTER_INTF]}
            port_count = self._core_plugin.get_ports_count(context,
                                                           port_filters)
            # port count is checked against 2 since the current port is already
            # added to db
            if port_count == 2:
                # This subnet is already part of some router
                LOG.error(_("FortinetL3ServicePlugin: adding redundant router "
                            "interface is not supported"))
                raise Exception(_("FortinetL3ServicePlugin:adding redundant router"
                                  "interface is not supported"))
            try:
                self.add_firewall_policy(context, tenant_id, network_id)
            except Exception:
                LOG.error(_("Failed to create Fortinet resources to add router "
                            "interface. info=%(info)s, router_id=%(router_id)s"),
                          {"info": info, "router_id": router_id})
                with excutils.save_and_reraise_exception():
                    self.remove_router_interface(context, router_id,
                                                     interface_info)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        """Deletes vlink, default router from Fortinet device."""
        LOG.debug("FortinetL3ServicePlugin.remove_router_interface called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        with context.session.begin(subtransactions=True):
            info = super(FortinetL3ServicePlugin, self).remove_router_interface(
                context, router_id, interface_info)
            try:
                subnet = self._core_plugin._get_subnet(context,
                                                       info['subnet_id'])
                LOG.debug(_("!!!!!!! info = %s, subnet=%s" % (info, subnet)))
                tenant_id = subnet["tenant_id"]
                network_id = subnet['network_id']
                self.delete_firewall_policy(context, tenant_id, network_id)
            except Exception:
                LOG.error(_("Fail remove of interface from Fortinet router "
                                "interface. info=%(info)s, "
                                "router_id=%(router_id)s") %
                              ({"info": info, "router_id": router_id}))
                raise Exception
        return True


    def create_floatingip(self, context, floatingip):
        """Create floating IP.

        :param context: Neutron request context
        :param floatingip: data for the floating IP being created
        :returns: A floating IP object on success

        As the l3 router plugin asynchronously creates floating IPs
        leveraging the l3 agent, the initial status for the floating
        IP object will be DOWN.
        """
        returned_obj = super(FortinetL3ServicePlugin, self).\
            create_floatingip(context, floatingip)
        try:
            self._allocate_floatingip(context, returned_obj)
            return returned_obj
        except Exception:
            super(FortinetL3ServicePlugin,
              self).delete_floatingip(context, returned_obj["id"])
            raise Exception("Failed to create the floating ip")


    def delete_floatingip(self, context, id):
        LOG.debug('delete_floatingip context=%s, id=%s' % (context, id))
        self._revoke_floatingip(context, id)
        super(FortinetL3ServicePlugin,
              self).delete_floatingip(context, id)

    def update_floatingip(self, context, id, floatingip):
        LOG.debug(_('##### floatingip=%s, id=%s' % (floatingip, id)))
        if floatingip["floatingip"]["port_id"]:
        # floating ip associate with VM port.
            res = super(FortinetL3ServicePlugin, self).\
                        update_floatingip(context, id, floatingip)
            LOG.debug(_('### return of update_floatingip=%s' % res))
            LOG.debug(_("##### associate floatingIP"))
            self._associate_floatingip(context, id, floatingip)
        else:
        # disassociate floating ip.
            LOG.debug(_("##### disassociate floatingIP"))
            self._disassociate_floatingip(context, id)
            res = super(FortinetL3ServicePlugin, self).\
            update_floatingip(context, id, floatingip)
            LOG.debug(_('### return of update_floatingip=%s' % res))
        return res


    def _associate_floatingip(self, context, id, floatingip):
        LOG.debug(_("##### floatingip=%s" % floatingip))
        session = context.session
        fip = self._get_floatingip(context, id).floating_ip_address
        tenant_id = floatingip["floatingip"]["tenant_id"]
        vdom_name = fortinet_db.get_namespace(context, tenant_id).vdom_name
        ip = self._get_ipallocation(session,
                                    floatingip["floatingip"]["port_id"])
        LOG.debug(_("##### ip=%s" % ip))
        if not getattr(ip, "ip_address", None):
            raise Exception("No ip address binding the port %s" % id)
        fixed_ip_address = ip.ip_address

        segment = db.get_network_segments(session, ip.network_id)
        LOG.debug(_("##### segment=%s" % segment))
        vlan_id= str(segment[0]["segmentation_id"])
        vip = self.add_vip(context, id, tenant_id, fixed_ip_address)
        LOG.debug(_('### vip=%s' % vip))
        if vip:
            try:
                message = {
                    "vdom_name": vip["vdom"],
                    "srcintf": vip["extintf"],
                    "dstintf": const.PREFIX["inf"] + vlan_id,
                    "dstaddr": vip["name"],
                    "nat": "enable"
                }
                self._add_firewall_policy(context, **message)

                # add firewall address
                kwargs = {
                    "name": fixed_ip_address,
                    "vdom_name": vdom_name,
                    "subnet": "%s 255.255.255.255" % fixed_ip_address,
                    "associated_interface": const.PREFIX["inf"] + vlan_id
                }
                self.add_address(context, **kwargs)

                # add firewall policy
                vl_inf = self._get_vl_inf(session, vdom_name)
                kwargs = {
                    "floating_ip_address": fip,
                    "allocated": True
                }
                cls = fortinet_db.Fortinet_FloatingIP_Allocation
                record = fortinet_db.get_record(session, cls, **kwargs)
                int_ip = self._get_ip(record.ip_subnet, 2)
                kwargs = {
                    "vdom_name": vdom_name,
                    "srcintf": const.PREFIX["inf"] + vlan_id,
                    "srcaddr": fixed_ip_address,
                    "dstintf": vl_inf[0],
                    "poolname": int_ip
                }
                policy_id = self._add_firewall_policy(context, **kwargs)
                self._head_firewall_policy(vdom_name, policy_id)

            except Exception:
                self.delete_vip(context, id)
                raise Exception("Fail to associate floatingip")
        return

    def _disassociate_floatingip(self, context, id):
        session = context.session
        floatingip = self._get_floatingip(context, id)
        vdom_name = fortinet_db.get_namespace(context,
                                              floatingip.tenant_id).vdom_name
        LOG.debug(_('### floatingip=%s' % floatingip))
        LOG.debug(_('### vdom_name=%s' % vdom_name))
        try:
            kwargs = {
                "vdom_name": vdom_name,
                "dstaddr": floatingip.floating_ip_address
            }
            self._delete_firewall_policy(context, **kwargs)
            self.delete_vip(context, id)

            # delete firewall policy
            vl_inf = self._get_vl_inf(session, vdom_name)
            kwargs = {
                "floating_ip_address": floatingip.floating_ip_address,
                "bound": True
            }
            cls = fortinet_db.Fortinet_FloatingIP_Allocation
            LOG.debug(_("##### kwargs=%s" % kwargs))
            record = fortinet_db.get_record(session, cls, **kwargs)
            LOG.debug(_("##### record=%s" % record))
            int_ip = self._get_ip(record.ip_subnet, 2)
            ip = self._get_ipallocation(session, floatingip.fixed_port_id)
            segment = db.get_network_segments(session, ip.network_id)
            LOG.debug(_("##### segment=%s" % segment))
            vlan_id= str(segment[0]["segmentation_id"])
            kwargs = {
                "vdom_name": vdom_name,
                "srcintf": const.PREFIX["inf"] + vlan_id,
                "srcaddr": floatingip.fixed_ip_address,
                "dstintf": vl_inf[0],
                "poolname": int_ip
            }
            LOG.debug(_("##### kwargs=%s" % kwargs))
            self._delete_firewall_policy(context, **kwargs)

            # delete firewall address
            kwargs = {
                "name": floatingip.fixed_ip_address,
                "vdom_name": const.EXT_VDOM
            }
            LOG.debug(_("##### kwargs=%s" % kwargs))
            self.delete_address(context, **kwargs)

        except Exception:
            raise Exception("Fail to disassociate floatingip")
        return


    def disassociate_floatingips(self, context, port_id, do_notify=True):
        LOG.debug(_("### disassociate_floatingips"))
        LOG.debug(_("### disassociate_floatingips port_id=%s" % (port_id)))
        return super(FortinetL3ServicePlugin,
                     self).disassociate_floatingips(context,
                                                    port_id,
                                                    do_notify=do_notify)


    def add_firewall_policy(self, context, tenant_id, network_id):
        LOG.debug(_("### add_firewall_policy"))
        session = context.session
        vdom_name = fortinet_db.get_namespace(context, tenant_id).vdom_name
        vlink_vlan = {
            "vdom_name": vdom_name,
            "allocated": True
        }
        cls = fortinet_db.Fortinet_Vlink_Vlan_Allocation
        dstintf = fortinet_db.get_record(session,
                                         cls,
                                         **vlink_vlan).inf_name_int_vdom

        srcintf = self._get_srcintf(session, network_id)
        kwargs = {
            "vdom_name": vdom_name,
            "srcintf": srcintf,
            "dstintf": dstintf,
            "nat": "enable"
        }
        self._add_firewall_policy(context, **kwargs)


    def _add_firewall_policy(self, context, **kwargs):
        session = context.session
        LOG.debug(_("### enter: kwargs= %s" % kwargs))
        record = fortinet_db.get_record(session,
                                        fortinet_db.Fortinet_Firewall_Policy,
                                        **kwargs)
        LOG.debug(_("### enter: record= %s" % record))
        if not record:
            try:
                message = kwargs.copy()
                if kwargs.has_key("vdom"):
                    kwargs.setdefault("vdom_name", kwargs["vdom"])
                    del kwargs["vdom"]
                record = fortinet_db.add_record(session,
                                   fortinet_db.Fortinet_Firewall_Policy,
                                   **kwargs)
                LOG.debug(_("### enter: record= %s" % record))

                if message.has_key("vdom_name"):
                    message.setdefault("vdom", message["vdom_name"])
                    del message["vdom_name"]
                resp = self._driver.request("ADD_FIREWALL_POLICY", **message)
                kwargs["edit_id"] = resp["results"]["mkey"]
                if kwargs.has_key("vdom"):
                    kwargs.setdefault("vdom_name", message["vdom"])
                    del kwargs["vdom"]
                LOG.debug(_("### kwargs= %s" % kwargs))
                fortinet_db.update_record(context, record, **kwargs)
                return resp["results"]["mkey"]
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("### Exception= %s" % Exception))
                    del_msg = {"vdom": message["vdom"], "id": message["edit_id"]}
                    self._driver.request("DELETE_FIREWALL_POLICY", **del_msg)
                    kwargs = {"id": record.id}
                    fortinet_db.delete_record(session,
                                   fortinet_db.Fortinet_Firewall_Policy,
                                   **kwargs)

    def delete_firewall_policy(self, context, tenant_id, network_id):
        LOG.debug(_("### delete_firewall_policy"))
        session = context.session
        vdom_name = fortinet_db.get_namespace(context, tenant_id).vdom_name
        srcintf = self._get_srcintf(session, network_id)
        kwargs = {"vdom_name": vdom_name, "srcintf": srcintf}
        self._delete_firewall_policy(context, **kwargs)

    def _delete_firewall_policy(self, context, **kwargs):
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Policy
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### delete_firewall_policy record=%s" % record))
        if record:
            try:
                if record.edit_id:
                    message = {"vdom": record.vdom_name, "id": record.edit_id}
                    resp = self._driver.request("DELETE_FIREWALL_POLICY",
                                                **message)
                    LOG.debug(_("### delete_firewall_policy type(res(http_status))=%s" % type(resp["http_status"])))
                    if httplib.OK == resp["http_status"]:
                        kwargs = {"id": record.id}
                        LOG.debug(_("### kwargs=%s" % kwargs))
                        fortinet_db.delete_record(session, cls, **kwargs)
            except Exception:
                LOG.error(_("Failed to delete firewall policy "
                                "interface. vdom_name=%(vdom_name)s, "
                                "id=%(id)s") %
                           ({"vdom_name": vdom_name, "id": record.edit_id}))
                raise Exception

    def _add_interface_by_subnet(self, context, router, subnet_id, owner):
        LOG.debug(_("!!!!!!! L3_fortinet _add_interface_by_subnet"))
        subnet = self._core_plugin._get_subnet(context, subnet_id)
        if not subnet['gateway_ip']:
            msg = _('Subnet for router interface must have a gateway IP')
            raise n_exc.BadRequest(resource='router', msg=msg)
        self._check_for_dup_router_subnet(context, router,
                                          subnet['network_id'],
                                          subnet_id,
                                          subnet['cidr'])
        fixed_ip = {'ip_address': subnet['gateway_ip'],
                    'subnet_id': subnet['id']}

        return self._core_plugin.create_port(context, {
            'port':
            {'tenant_id': subnet['tenant_id'],
             'network_id': subnet['network_id'],
             'fixed_ips': [fixed_ip],
             'mac_address': self._get_mac(),
             'admin_state_up': True,
             'device_id': router.id,
             'device_owner': owner,
             'name': ''}})

    def _allocate_floatingip(self, context, obj):
        """
        1. mapping floatingip to the one of a pair of internal ips based on
           the vip function.
        2. add another ip of the ip pair to the secondaryip list of
           the external interface.
        """
        session = context.session
        floatingip_id = obj["id"]
        floatingip = self._get_floatingip(context, floatingip_id)
        LOG.debug(_("### floatingip= %s" % floatingip))
        fip = floatingip["floating_ip_address"]
        tenant_id = obj["tenant_id"]
        tenant_vdom = fortinet_db.get_namespace(context, tenant_id).vdom_name
        vl_inf = self._get_vl_inf(session, tenant_vdom)
        vip = self.add_vip(context, floatingip_id, tenant_id)
        if vip:
            try:
                secondaryip = self.add_secondaryip(context,
                                                   floatingip_id,
                                                   tenant_id)
                if secondaryip:
                    message = {
                        "vdom_name": const.EXT_VDOM,
                        "srcintf": self._fortigate["ext_interface"],
                        "dstintf": secondaryip["name"],
                        "dstaddr": vip["name"],
                        "nat": "enable"
                    }
                    LOG.debug(_("### message= %s" % message))
                    self._add_firewall_policy(context, **message)

                    # add firewall ippool
                    kwargs = {
                        "name": fip,
                        "vdom_name": const.EXT_VDOM,
                        "startip": fip
                    }
                    LOG.debug(_("### kwargs= %s" % kwargs))
                    self.add_ippool(context, **kwargs)

                    # add firewall address
                    kwargs = {
                        "floating_ip_address": fip,
                        "allocated": True
                    }
                    cls = fortinet_db.Fortinet_FloatingIP_Allocation
                    record = fortinet_db.get_record(session, cls, **kwargs)
                    int_ip = self._get_ip(record.ip_subnet, 2)
                    LOG.debug(_("record=%s" %record))
                    LOG.debug(_("int_ip=%s" %int_ip))
                    kwargs = {
                        "name": int_ip,
                        "vdom_name": const.EXT_VDOM,
                        "subnet": "%s 255.255.255.255" % int_ip
                    }
                    LOG.debug(_("kwargs=%s" %kwargs))
                    self.add_address(context, **kwargs)

                    # add firewall policy
                    kwargs = {
                        "vdom_name": const.EXT_VDOM,
                        "srcintf": vl_inf[1],
                        "srcaddr": int_ip,
                        "dstintf": self._fortigate["ext_interface"],
                        "poolname": fip
                    }
                    LOG.debug(_("kwargs=%s" %kwargs))
                    policy_id = self._add_firewall_policy(context, **kwargs)
                    self._head_firewall_policy(const.EXT_VDOM, policy_id)

                    # add ippool of int_ip
                    kwargs = {
                        "name": int_ip,
                        "vdom_name": tenant_vdom,
                        "startip": int_ip
                    }
                    LOG.debug(_("kwargs=%s" %kwargs))
                    self.add_ippool(context, **kwargs)

                else:
                    self.delete_vip(context, floatingip_id)
            except Exception:
                self.delete_vip(context, floatingip_id)
                raise Exception("Failed to add secondaryip")


    def _revoke_floatingip(self, context, id):
        session = context.session
        floatingip = self._get_floatingip(context, id)
        LOG.debug(_("### floatingip= %s" % floatingip))
        tenant_id = floatingip["tenant_id"]
        vdom_name = fortinet_db.get_namespace(context, tenant_id).vdom_name
        cls = fortinet_db.Fortinet_FloatingIP_Allocation
        floating_ip_address = floatingip["floating_ip_address"]
        kwargs = {
            "floating_ip_address": floating_ip_address,
            "allocated": True
        }
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### record= %s" % record))
        if record:
            try:
                vl_inf = self._get_vl_inf(session, vdom_name)
                kwargs = {
                    "vdom_name": const.EXT_VDOM,
                    "srcintf": self._fortigate["ext_interface"],
                    "dstintf": vl_inf[1],
                    "dstaddr": record.vip_name
                }
                LOG.debug(_("### kwargs= %s" % kwargs))
                self._delete_firewall_policy(context, **kwargs)
                if self.delete_secondaryip(context, id, tenant_id):
                    self.delete_vip(context, id)

                # delete ippool of the int_ip in the tenant vdom
                #cls = fortinet_db.Fortinet_FloatingIP_Allocation
                #record = fortinet_db.get_record(session, cls, **kwargs)
                LOG.debug(_("### record= %s" % record))
                int_ip = self._get_ip(record.ip_subnet, 2)
                kwargs = {
                    "name": int_ip,
                    "vdom_name": vdom_name
                }
                LOG.debug(_("### kwargs= %s" % kwargs))
                self.delete_ippool(context, **kwargs)

                # delete firewall policy
                kwargs = {
                    "vdom_name": const.EXT_VDOM,
                    "srcintf": vl_inf[1],
                    "srcaddr": int_ip,
                    "dstintf": self._fortigate["ext_interface"],
                    "poolname": floating_ip_address
                }
                LOG.debug(_("### kwargs= %s" % kwargs))
                self._delete_firewall_policy(context, **kwargs)

                # delete firewall addresses of int_ip in the external vdom
                kwargs = {
                    "name": int_ip,
                    "vdom_name": const.EXT_VDOM
                }
                LOG.debug(_("### kwargs= %s" % kwargs))
                self.delete_address(context, **kwargs)

                # delete ippool of floatingip in the external vdom
                kwargs = {
                    "name": floating_ip_address,
                    "vdom_name": const.EXT_VDOM
                }
                LOG.debug(_("### kwargs= %s" % kwargs))
                self.delete_ippool(context, **kwargs)
            except Exception:
                raise Exception("Failed to delete secondaryip")


    def _head_firewall_policy(self, vdom, id):
        LOG.debug(_("_head_firewall_policy, vdom=%s, id=%s" %(vdom, id)))
        message = {
            "vdom": vdom
        }
        resp = self._driver.request("GET_FIREWALL_POLICY", **message)
        LOG.debug(_("#####  response=%s" %resp))
        if resp["results"]:
            headid = resp["results"][0]["policyid"]
            message.setdefault("id", id)
            message.setdefault("before", headid)
            self._driver.request("MOVE_FIREWALL_POLICY", **message)


    def add_secondaryip(self, context, floatingip_id, tenant_id):
        LOG.debug(_("add_secondaryip"))
        return self._secondaryip("ADD", context, floatingip_id, tenant_id)

    def delete_secondaryip(self, context, floatingip_id, tenant_id):
        LOG.debug(_("### delete_secondaryip"))
        return self._secondaryip("DELETE", context, floatingip_id, tenant_id)


    def _secondaryip(self, op, context, floatingip_id, tenant_id):
        LOG.debug(_("_secondaryip"))
        secondaryips = []
        session = context.session
        floatingip = self._get_floatingip(context, floatingip_id)
        LOG.debug(_("### floatingip= %s" % floatingip))
        floating_ip_address = floatingip["floating_ip_address"]
        vdom_name = fortinet_db.get_namespace(context, tenant_id).vdom_name
        kwargs = {
            "floating_ip_address": floating_ip_address,
            "allocated": True
        }
        cls = fortinet_db.Fortinet_FloatingIP_Allocation
        record = fortinet_db.get_record(session, cls, **kwargs)
        if not record:
            LOG.error(_("The floating ip %s is not recorded"
                            % floating_ip_address))
            raise Exception("The floating ip %s cannot not be found"
                            % floating_ip_address)
        try:
            if op == "ADD":
                kws = {"vdom_name": vdom_name}
            elif op == "DELETE":
                kws = {"vdom_name": None}
            fortinet_db.update_record(context, record, **kws)
            kwargs = {"vdom_name": vdom_name, "allocated": True}
            records = fortinet_db.get_records(session, cls, **kwargs)
            for _record in records:
                secondaryips.append(self._get_ip_mask(_record.ip_subnet))
            #secondaryips.append(self._get_ip_mask(record.ip_subnet))
            LOG.debug(_("### secondaryips= %s" % secondaryips))
            vl_inf = self._get_vl_inf(session, vdom_name)
            message = {
                "name": vl_inf[1],
                "vdom": const.EXT_VDOM,
                "secondaryips": secondaryips
            }
            resp = self._driver.request("SET_VLAN_INTERFACE", **message)
            LOG.debug(_("### resp= %s" % resp))
            return message
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("### Exception= %s" % Exception))
        return None


    def add_ippool(self, context, **kwargs):
        LOG.debug(_("### add_ippool"))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_IPPool
        record = fortinet_db.get_record(session, cls, **kwargs)
        if "name" in kwargs:
            kwargs.setdefault("startip", kwargs["name"])
            kwargs.setdefault("endip", kwargs["startip"])
        LOG.debug(_("### record = %s" % record))
        if not record:
            try:
                # use vdom first
                if kwargs.has_key("vdom_name"):
                    kwargs.setdefault("vdom", kwargs["vdom_name"])
                    del kwargs["vdom_name"]
                self._driver.request("ADD_FIREWALL_IPPOOL", **kwargs)

                if kwargs.has_key("vdom"):
                    kwargs.setdefault("vdom_name", kwargs["vdom"])
                    del kwargs["vdom"]
                fortinet_db.add_record(session, cls, **kwargs)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("### Exception= %s" % Exception))
                    self._driver.request("DELETE_FIREWALL_IPPOOL", **kwargs)
                    fortinet_db.delete_record(session, cls, **kwargs)


    def delete_ippool(self, context, **kwargs):
        LOG.debug(_("### delete_ippool"))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_IPPool
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### record = %s" % record))
        if not record:
            return None
        try:
            # use vdom first
            if kwargs.has_key("vdom_name"):
                kwargs.setdefault("vdom", kwargs["vdom_name"])
                del kwargs["vdom_name"]
            self._driver.request("DELETE_FIREWALL_IPPOOL", **kwargs)

            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom_name", kwargs["vdom"])
                del kwargs["vdom"]
            fortinet_db.delete_record(session, cls, **kwargs)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("### Exception= %s" % Exception))


    def add_address(self, context, **kwargs):
        LOG.debug(_("### add_address"))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Address
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### record = %s" % record))
        LOG.debug(_("### kwargs = %s" % kwargs))
        if not record:
            try:
                if kwargs.has_key("vdom_name"):
                    kwargs.setdefault("vdom", kwargs["vdom_name"])
                    del kwargs["vdom_name"]
                self._driver.request("ADD_FIREWALL_ADDRESS", **kwargs)

                if kwargs.has_key("vdom"):
                    kwargs.setdefault("vdom_name", kwargs["vdom"])
                    del kwargs["vdom"]
                fortinet_db.add_record(session, cls, **kwargs)
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
            if kwargs.has_key("vdom_name"):
                kwargs.setdefault("vdom", kwargs["vdom_name"])
                del kwargs["vdom_name"]
            self._driver.request("DELETE_FIREWALL_ADDRESS", **kwargs)

            if kwargs.has_key("vdom"):
                kwargs.setdefault("vdom_name", kwargs["vdom"])
                del kwargs["vdom"]
            fortinet_db.delete_record(session, cls, **kwargs)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("### Exception= %s" % Exception))

    def add_addrgrp(self, context, **kwargs):
        LOG.debug(_("### add_addrgrp"))
        session = context.session
        cls = fortinet_db.Fortinet_Firewall_Address
        if not kwargs.get("members", None):
            LOG.debug(_("### there is no member"))
            return
        #record = fortinet_db.get_record(session, cls, **kwargs)
        #LOG.debug(_("### record = %s" % record))
        try:
            if kwargs.has_key("vdom_name"):
                kwargs.setdefault("vdom", kwargs["vdom_name"])
                del kwargs["vdom_name"]
            self._driver.request("ADD_FIREWALL_ADDRGRP", **kwargs)
            for name in kwargs["members"]:
                addrinfo = {
                    "name": name,
                    "vdom_name": kwargs["vdom"]
                }
                record = fortinet_db.get_record(session, cls, **addrinfo)
                if not record.group:
                    addrinfo.setdefault("group", kwargs["name"])
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
                        "vdom_name": kwargs["vdom"]
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
                if kwargs.has_key("vdom_name"):
                    kwargs.setdefault("vdom", kwargs["vdom_name"])
                    del kwargs["vdom_name"]
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
        LOG.debug(_("### delete_member_addrgrp"))
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
            if kwargs.has_key("vdom_name"):
                kwargs.setdefault("vdom", kwargs["vdom_name"])
                del kwargs["vdom_name"]
            members = []
            for record in records:
                if record.name in kwargs["members"]:
                    fortinet_db.update_record(context, record, group=None)
                else:
                    members.append(record.name)
            kwargs["members"] = members
            self._driver.request("SET_FIREWALL_ADDRGRP", **kwargs)
            LOG.debug(_("### The member %(member)s "
                        "is kept in the group"),
                        {"member": members})
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_("### Exception= %s" % Exception))


    def add_vip(self, context, floatingip_id, tenant_id, mappedip=None):
        LOG.debug(_("### add_vip"))
        session = context.session
        vdom_name = fortinet_db.get_namespace(context, tenant_id).vdom_name
        floatingip = self._get_floatingip(context, floatingip_id)
        LOG.debug(_("### floatingip= %s" % floatingip))
        floating_ip_address = floatingip["floating_ip_address"]
        kwargs = {"floating_ip_address": floating_ip_address}
        cls = fortinet_db.Fortinet_FloatingIP_Allocation
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### record= %s" % record))
        if record:
            if record.allocated and record.bound:
                LOG.debug(_("The floating_ip_address %s already used"
                            % floating_ip_address))
                raise Exception("The floating ip %s already used"
                                % floating_ip_address)
            elif record.allocated and not record.bound:
                if vdom_name == const.EXT_VDOM:
                    raise Exception("vdom_name %s is invalid" % vdom_name)
                try:
                    kwargs = {"bound": True}
                    fortinet_db.update_record(context, record, **kwargs)
                    vl_inf = self._get_vl_inf(session, vdom_name)
                    if not mappedip:
                        mappedip = floatingip["fixed_ip_address"]
                    message = {
                        "vdom": vdom_name,
                        "name": record.vip_name,
                        "extip": self._get_ip(record.ip_subnet, 2),
                        "extintf": vl_inf[0],
                        "mappedip": mappedip
                    }
                    resp = self._driver.request("ADD_FIREWALL_VIP", **message)
                    LOG.debug(_("### resp= %s" % resp))
                    return message
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.error(_("### Exception= %s" % Exception))
                        kwargs = {"vdom_name": None, "bound": False}
                        fortinet_db.update_record(context, record, **kwargs)
            else:
                LOG.debug(_("The floating_ip_address %s is not allocated"
                            % floating_ip_address))
                raise Exception("The floating ip %s not allocated"
                                % floating_ip_address)
        else:
            kwargs = {"allocated": False}
            record = fortinet_db.get_record(session, cls, **kwargs)
            LOG.debug(_("### record=%s" % record))
            if not record:
                LOG.debug(_("There is not any available internal ipsubnet"))
                raise Exception("Error: The internal ipsubnet is full")
            try:
                kwargs = {
                    "floating_ip_address": floating_ip_address,
                    "vip_name": floating_ip_address,
                    "allocated": True
                }
                fortinet_db.update_record(context, record, **kwargs)
                message = {
                    "vdom": const.EXT_VDOM,
                    "name": kwargs["vip_name"],
                    "extip": kwargs["vip_name"],
                    "extintf": self._fortigate["ext_interface"],
                    "mappedip": self._get_ip(record.ip_subnet, 2)
                }
                LOG.debug(_("### message=%s" % message))
                resp = self._driver.request("ADD_FIREWALL_VIP", **message)
                LOG.debug(_("### resp= %s" % resp))
                return message
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_("### Exception= %s" % Exception))
                    kwargs = {
                        "floatingip_id": None,
                        "vip_name": None,
                        "allocated": False
                    }
                    fortinet_db.update_record(context, record, **kwargs)
        return None


    def delete_vip(self, context, floatingip_id):
        LOG.debug(_("### delete_vip"))
        session = context.session
        floatingip = self._get_floatingip(context, floatingip_id)
        floating_ip_address = floatingip["floating_ip_address"]
        LOG.debug(_("### floatingip= %s" % floatingip))
        kwargs = {
            "floating_ip_address": floating_ip_address,
            "allocated": True
        }
        cls = fortinet_db.Fortinet_FloatingIP_Allocation
        record = fortinet_db.get_record(session, cls, **kwargs)
        LOG.debug(_("### record= %s" % record))
        if not record:
            LOG.debug(_("There is not any record with %s" % floatingip))
            return False
        if not record.bound:
            try:
                message = {
                    "vdom": const.EXT_VDOM,
                    "name": record.vip_name
                }
                LOG.debug(_("### message= %s" % message))
                resp = self._driver.request("DELETE_FIREWALL_VIP", **message)
                kwargs = {
                    "floating_ip_address": None,
                    "allocated": False,
                    "vip_name": None
                }
                fortinet_db.update_record(context, record, **kwargs)
                return True
            except Exception:
                LOG.error(_("### Exception= %s" % Exception))
                raise Exception
        else:
            try:
                message = {
                        "vdom": record.vdom_name,
                        "name": record.vip_name
                }
                LOG.debug(_("### message= %s" % message))
                resp = self._driver.request("DELETE_FIREWALL_VIP", **message)
                kwargs = {
                    # "floating_ip_address": None,
                    "bound": False
                }
                if not record.allocated:
                    kwargs["vip_name"] = None
                fortinet_db.update_record(context, record, **kwargs)
                return True
            except Exception:
                LOG.error(_("### Exception= %s" % Exception))
                raise Exception
        return False


    def _get_mac(self, interface=None):
        mac_address = None
        if not interface:
            interface = self._fortigate["int_interface"]
        message = {
        "name": interface
        }
        res = self._driver.request("GET_VLAN_INTERFACE", **message)
        if res["http_status"] == httplib.OK:
            mac_address = res["results"][0]["macaddr"]
        LOG.debug(_("### mac_address= %s" % mac_address))
        return mac_address

    @staticmethod
    def _get_ip_mask(ip_subnet, position=1):
        try:
            ip_mask = "%s %s" % (netaddr.IPNetwork(ip_subnet)[position],
                                 netaddr.IPNetwork(ip_subnet).netmask)
        except Exception:
            raise Exception
        return ip_mask

    @staticmethod
    def _get_ip(ip_subnet, position=1):
        try:
            ip = "%s" % netaddr.IPNetwork(ip_subnet)[position]
        except Exception:
            raise Exception
        return ip

    @staticmethod
    def _get_vl_inf(session, vdom_name):
        kwargs = {"vdom_name": vdom_name, "allocated": True}
        cls = fortinet_db.Fortinet_Vlink_Vlan_Allocation
        record = fortinet_db.get_record(session, cls, **kwargs)
        if record:
            return (record.inf_name_int_vdom, record.inf_name_ext_vdom)
        return None

    @staticmethod
    def _get_srcintf(session, network_id):
        ml2_network_seg = db.get_network_segments(session, network_id)
        LOG.debug(_("### ml2_network_seg= %s" % ml2_network_seg))
        srcintf = const.PREFIX["inf"] + \
                  str(ml2_network_seg[0]["segmentation_id"])
        return srcintf

    @staticmethod
    def _get_ipallocation(session, port_id=None, **kwargs):
        cls = models_v2.IPAllocation
        if port_id:
            kwargs["port_id"] = port_id
        if kwargs:
            return fortinet_db.get_record(session, cls, **kwargs)
        else:
            return None

