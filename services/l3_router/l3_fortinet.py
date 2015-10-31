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
from neutron.plugins.ml2.drivers.fortinet.tasks import tasks
from neutron.plugins.ml2.drivers.fortinet.common import utils

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
        self.task_manager = tasks.TaskManager()
        self.task_manager.start()
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

        api_server = [(self._fortigate['address'], 80, False)]
        self._driver = client.FortiosApiClient(api_server,
            self._fortigate['username'], self._fortigate['password'])

    def update_router(self, context, id, router):
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
            port = db.get_port(context.session, info['port_id'])
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
            tenant_id = port['tenant_id']
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
                raise Exception(_("FortinetL3ServicePlugin:adding redundant "
                                  "router interface is not supported"))
            try:
                utils.add_fwpolicy(self, context,
                                   vdom=namespace.vdom,
                                   srcintf='any',
                                   srcaddr=addrgrp_name,
                                   dstintf='any',
                                   dstaddr=addrgrp_name,
                                   nat='disable')


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
                tenant_id = subnet['tenant_id']
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
        self._release_floatingip(context, id)
        super(FortinetL3ServicePlugin,
              self).delete_floatingip(context, id)

    def update_floatingip(self, context, id, floatingip):
        LOG.debug(_('##### floatingip=%s, id=%s' % (floatingip, id)))
        if floatingip["floatingip"]["port_id"]:
        # floating ip associate with VM port.
            res = super(FortinetL3ServicePlugin, self).\
                        update_floatingip(context, id, floatingip)
            self._associate_floatingip(context, id, floatingip)
        else:
        # disassociate floating ip.
            self._disassociate_floatingip(context, id)
            res = super(FortinetL3ServicePlugin, self).\
            update_floatingip(context, id, floatingip)
        return res


    def _associate_floatingip(self, context, id, floatingip):
        #LOG.debug(_("##### floatingip=%s" % floatingip))
        #session = context.session
        l3db_fip = self._get_floatingip(context, id)
        db_namespace = fortinet_db.query_record(context,
                                fortinet_db.Fortinet_ML2_Namespace,
                                tenant_id=l3db_fip.tenant_id)

        db_fip = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_FloatingIP_Allocation,
                            floating_ip_address=l3db_fip.floating_ip_address,
                            allocated=True)


        #fip = self._get_floatingip(context, id).floating_ip_address
        #tenant_id = floatingip['floatingip']['tenant_id']
        #vdom_name = fortinet_db.get_namespace(context, tenant_id).vdom_name
        #ip = self._get_ipallocation(session,
        #                            floatingip["floatingip"]["port_id"])
        #LOG.debug(_("##### ip=%s" % ip))
        #if not getattr(ip, "ip_address", None):
        #    raise Exception("No ip address binding the port %s" % id)
        #fixed_ip_address = ip.ip_address

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

        srcintf = self.utils.get_srcintf(session, network_id)
        kwargs = {
            "vdom_name": vdom_name,
            "srcintf": srcintf,
            "dstintf": dstintf,
            "nat": "enable"
        }

        utils.add_fwpolicy(self, context,
                           vdom=namespace.vdom,
                           srcintf=' ',
                           dstintf=fortinet_db.query_record(context, fortinet_db.Fortinet_Vlink_Vlan_Allocation, vdom=vdom, allocated=True).inf_name_int_vdom,
                           nat='enable')


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
        srcintf = self.utils.get_srcintf(session, network_id)
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
             'mac_address': self.utils.get_mac(self),
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

        obj example:
        {
            'floating_network_id': u'1c1dbecc-9dac-4311-a346-f147a04c8dc8',
            'router_id': None,
            'fixed_ip_address': None,
            'floating_ip_address': u'10.160.37.113',
            'tenant_id': u'3998b33381fb48f694369689065a3760',
            'status': 'DOWN',
            'port_id': None,
            'id': '5ec1b08b-77c1-4e39-80ac-224ee937ee9f'
        }

        The floatingip is a instance of neutron.db.l3_db.FloatingIP, example:
        {
            tenant_id=u'3998b33381fb48f694369689065a3760',
            id=u'25e1588a-5ec5-4fbc-bdef-eff8713da8f8',
            floating_ip_address=u'10.160.37.111',
            floating_network_id=u'1c1dbecc-9dac-4311-a346-f147a04c8dc8',
            floating_port_id=u'4b4120d4-77f9-4f82-b823-05876929a1c4',
            fixed_port_id=None,
            fixed_ip_address=None,
            router_id=None,
            last_known_router_id=None,
            status=u'DOWN'
        }
        """
        db_namespace = fortinet_db.query_record(context,
                                        fortinet_db.Fortinet_ML2_Namespace,
                                        tenant_id=obj['tenant_id'])

        db_fip = utils.add_record(self, context,
                                fortinet_db.Fortinet_FloatingIP_Allocation,
                                vdom=db_namespace.vdom,
                                floating_ip_address=obj['floating_ip_address'],
                                vip_name=obj['floating_ip_address'])

        utils.add_vip(self, context,
                      vdom=const.EXT_VDOM,
                      name=db_fip.vip_name,
                      extip=db_fip.floating_ip_address,
                      extintf=self._fortigate['ext_interface'],
                      mappedip=utils.getip(db_fip.ip_subnet, 2))

        int_inf, ext_inf = utils.get_vlink_inf(self, context,
                                               vdom=db_namespace.vdom)
        utils.add_secondaryip(self, context, name=ext_inf, vdom=const.EXT_VDOM,
                              ip=utils.getip(db_fip.ip_subnet, 1))

        utils.add_fwpolicy(self, context,
                           vdom_name=const.EXT_VDOM,
                           srcintf='any',
                           dstintf=ext_inf,
                           dstaddr=db_fip.vip_name,
                           nat='enable')

        utils.add_fwippool(self, context,
                           name=db_fip.floating_ip_address,
                           vdom=const.EXT_VDOM,
                           startip=db_fip.floating_ip_address)

        ipaddr = utils.get_ipaddr(db_fip.ip_subnet, 2)
        utils.add_fwaddress(self, context,
                            name=ipaddr,
                            vdom=const.EXT_VDOM,
                            subnet="%s 255.255.255.255" % ipaddr)

        db_fwpolicy = utils.add_fwpolicy(self, context,
                           vdom_name=const.EXT_VDOM,
                           srcintf=ext_inf,
                           srcaddr=ipaddr,
                           dstintf=self._fortigate['ext_interface'],
                           poolname=db_fip.floating_ip_address)
        utils.head_firewall_policy(self, context,
                                   vdom=const.EXT_VDOM,
                                   id=db_fwpolicy.edit_id)

        utils.add_fwippool(self, context,
                           name=ipaddr,
                           vdom=db_namespace.vdom,
                           startip=ipaddr)


    def _release_floatingip(self, context, id):
        """
        :param context:
        :param id: the floatingip id in neutron.db.l3_db.FloatingIP.
        {
                tenant_id=u'3998b33381fb48f694369689065a3760',
                id=u'25e1588a-5ec5-4fbc-bdef-eff8713da8f8',
                floating_ip_address=u'10.160.37.111',
                floating_network_id=u'1c1dbecc-9dac-4311-a346-f147a04c8dc8',
                floating_port_id=u'4b4120d4-77f9-4f82-b823-05876929a1c4',
                fixed_port_id=None,
                fixed_ip_address=None,
                router_id=None,
                last_known_router_id=None,
                status=u'DOWN'
        }
        :return:
        """
        l3db_fip = self._get_floatingip(context, id)
        db_namespace = fortinet_db.query_record(context,
                                fortinet_db.Fortinet_ML2_Namespace,
                                tenant_id=l3db_fip.tenant_id)

        db_fip = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_FloatingIP_Allocation,
                            floating_ip_address=l3db_fip.floating_ip_address,
                            allocated=True)
        if not db_fip:
            return

        int_inf, ext_inf = utils.get_vlink_inf(self, context,
                                           vdom=db_namespace.vdom)
        ipaddr = utils.get_ipaddr(db_fip.ip_subnet, 2)

        utils.delete_fwippool(self, context,
                              name=ipaddr,
                              vdom=db_namespace.vdom,
                              startip=ipaddr)

        utils.delete_fwpolicy(self, context,
                              vdom_name=const.EXT_VDOM,
                              srcintf=ext_inf,
                              srcaddr=ipaddr,
                              dstintf=self._fortigate['ext_interface'],
                              poolname=db_fip.floating_ip_address)

        utils.delete_fwaddress(self, context,
                               name=ipaddr,
                               vdom=const.EXT_VDOM,
                               subnet="%s 255.255.255.255" % ipaddr)

        utils.delete_fwippool(self, context,
                              name=db_fip.floating_ip_address,
                              vdom=const.EXT_VDOM,
                              startip=db_fip.floating_ip_address)

        utils.delete_fwpolicy(self, context,
                              vdom=const.EXT_VDOM,
                              srcintf='any',
                              dstintf=ext_inf,
                              dstaddr=l3db_fip.floating_ip_address)

        utils.delete_secondaryip(self, context,
                                 name=ext_inf,
                                 vdom=const.EXT_VDOM,
                                 ip=utils.getip(db_fip.ip_subnet, 1))

        utils.delete_vip(self, context,
                         vdom=const.EXT_VDOM,
                         name=db_fip.vip_name,
                         extip=db_fip.floating_ip_address,
                         extintf=self._fortigate['ext_interface'],
                         mappedip=utils.getip(db_fip.ip_subnet, 2))

        fortinet_db.delete_record(self, context,
                        fortinet_db.Fortinet_FloatingIP_Allocation,
                        vdom=db_namespace.vdom,
                        floating_ip_address=db_fip.floating_ip_address,
                        vip_name=db_fip.floating_ip_address)


    @staticmethod
    def _get_ipallocation(session, port_id=None, **kwargs):
        cls = models_v2.IPAllocation
        if port_id:
            kwargs["port_id"] = port_id
        if kwargs:
            return fortinet_db.query_record(session, cls, **kwargs)
        else:
            return None

