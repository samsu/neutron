# Copyright 2015 Fortinet Inc.
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

import netaddr
import json

from neutron.db import l3_db
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.fortinet.common import resources as resources
from neutron.plugins.ml2.drivers.fortinet.common import constants as const
from neutron.plugins.ml2.drivers.fortinet.tasks import constants as t_consts
from neutron.plugins.ml2.drivers.fortinet.db import models as fortinet_db
from neutron.plugins.ml2.drivers.fortinet.api_client import exception

LOG = logging.getLogger(__name__)

def add_record(obj, context, cls, **kwargs):
    res = cls.add_record(context, **kwargs)
    if res.get('rollback', {}):
        obj.task_manager.add(getid(context), **res['rollback'])
    return res.get('result', None)

def op(obj, context, func, **data):
    res = func(obj._driver, data)
    if res.get('rollback', {}):
        obj.task_manager.add(getid(context), **res['rollback'])
    return res.get('result', res)

def getid(context):
    id = getattr(context, 'request_id', None)
    if not id:
        raise ValueError("not get request_id")
    return id

def getip(ipsubnet, place):
    return "%s %s" % (ipsubnet[place], ipsubnet.netmask)


def update_status(obj, context, status):
    obj.task_manager.update_status(getid(context), status)

def _rollback_on_err(obj, context, err):
    update_status(obj, context, t_consts.TaskStatus.ROLLBACK)
    resources.Exinfo(err)


def add_vdom(obj, context, **kwargs):
    namespace = add_record(obj, context, fortinet_db.Fortinet_ML2_Namespace,
                           **kwargs)
    try:
        op(obj, context, resources.Vdom.get, name=namespace.vdom)
    except exception.ResourceNotFound:
        op(obj, context, resources.Vdom.add, name=namespace.vdom)
    return namespace


def delete_vdom(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_Namespace
    namespace = fortinet_db.query_record(obj, context, cls, **kwargs)
    if namespace:
        try:
            op(obj, context, resources.Vdom.get, name=namespace.vdom)
            op(obj, context, resources.Vdom.delete, name=namespace.vdom)
        except Exception as e:
            resources.Exinfo(e)
        fortinet_db.delete_record(context, cls, **kwargs)
    return namespace


def add_reservedip(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_ReservedIP
    reserved_ip = add_record(obj, context, cls, **kwargs)
    db_reservedips = fortinet_db.query_records(context, cls,
                                        subnet_id=kwargs.get('subnet_id'))
    db_subnet = fortinet_db.query_record(context,
                                         fortinet_db.Fortinet_ML2_Subnet,
                                         subnet_id=kwargs.get('subnet_id'))
    if db_subnet:
        reserved_addresses = []
        for rsrvdip in db_reservedips:
            reserved_addresses.append({ 'id': rsrvdip.edit_id,
                                        'ip': rsrvdip.ip,
                                        'mac': rsrvdip.mac })

        op(obj, context, resources.DhcpServerRsvAddr.set,
           id=db_subnet.mkey,
           vdom=kwargs.get('vdom'),
           reserved_address=json.dumps(reserved_addresses))
        # TODO: add rollback of dhcpserver set


def delete_reservedip(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_ML2_ReservedIP
    reserved_ip = fortinet_db.query_record(obj, context, cls, **kwargs)

    if reserved_ip:
        db_reservedips = fortinet_db.query_records(context, cls,
                                        subnet_id=reserved_ip.subnet_id)
        db_reservedips.remove(reserved_ip)
        reserved_addresses = []
        for rsrvdip in db_reservedips:
            reserved_addresses.append({ 'id': rsrvdip.edit_id,
                                        'ip': rsrvdip.ip,
                                        'mac': rsrvdip.mac })
        db_subnet = fortinet_db.query_record(context,
                                             fortinet_db.Fortinet_ML2_Subnet,
                                             subnet_id=reserved_ip.subnet_id)
        if db_subnet:
            op(obj, context, resources.DhcpServer.set,
               id=db_subnet.mkey,
               vdom=reserved_ip.vdom,
               reserved_address=json.dumps(reserved_addresses))
        fortinet_db.delete_record(context, cls, **kwargs)


def add_fwaddress(obj, context, **kwargs):
    return add_resource(obj, context, fortinet_db.Fortinet_Firewall_Address,
                        resources.FirewallAddress, **kwargs)


def delete_fwaddress(obj, context, **kwargs):
    return delete_resource(obj, context, fortinet_db.Fortinet_Firewall_Address,
                           resources.FirewallAddress, **kwargs)


def add_fwippool(obj, context, **kwargs):
    return add_resource(obj, context, fortinet_db.Fortinet_Firewall_IPPool,
                        resources.FirewallIppool, **kwargs)


def delete_fwippool(obj, context, **kwargs):
    return delete_resource(obj, context, fortinet_db.Fortinet_Firewall_IPPool,
                           resources.FirewallIppool, **kwargs)


def add_fwpolicy(obj, context, **kwargs):
    record = add_record(obj, context,
                        fortinet_db.Fortinet_Firewall_Policy, **kwargs)
    if getattr(record, 'edit_id'):
        try:
            op(obj, context, resources.FirewallIppool.get,
               vdom=record.vdom, id=record.edit_id)
            return record
        except exception.ResourceNotFound:
            pass
    res = op(obj, context, resources.Fortinet_Firewall_Policy.add, **kwargs)
    record.update(context, record, edit_id=res['mkey'])
    return record


def delete_fwpolicy(obj, context, **kwargs):
    cls = fortinet_db.Fortinet_Firewall_Policy
    record = fortinet_db.query_record(context, cls, **kwargs)
    if getattr(record, 'edit_id'):
        try:
            op(obj, context, resources.FirewallPolicy.delete,
               vdom=record.vdom, id=record.edit_id)
        except Exception as e:
            resources.Exinfo(e)
    fortinet_db.delete_record(context, cls, **kwargs)


def add_resource(obj, context, cls, resource, **kwargs):
    record = add_record(obj, context, cls, **kwargs)
    if record:
        try:
            op(obj, context, resource.get, vdom=record.vdom, name=record.name)
        except exception.ResourceNotFound:
            op(obj, context, resource.add, **kwargs)
    return record


def delete_resource(obj, context, cls, resource, **kwargs):
    record = fortinet_db.query_record(context, cls, **kwargs)
    if record:
        try:
            op(obj, context, resource.get, vdom=record.vdom, name=record.name)
            op(obj, context, resource.delete,
               vdom=record.vdom, name=record.name)
        except exception.ResourceNotFound:
            pass
    return fortinet_db.delete_record(context, cls, **kwargs)


def add_vip(self, context, **kwargs):
    """ should add a structure of kwargs as a example"""
    LOG.debug(_("### floatingip_id, tenant_id, mappedip=None"))
    db_namespace = fortinet_db.query_record(context,
                                            fortinet_db.Fortinet_ML2_Namespace,
                                            tenant_id=kwargs.get('tenant_id'))
    db_floatingip = fortinet_db.query_record(context, )
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
                #vl_inf = self._get_vl_inf(session, vdom_name)
                if not mappedip:
                    mappedip = floatingip["fixed_ip_address"]
                message = {
                    "vdom": vdom_name,
                    "name": record.vip_name,
                    "extip": self._get_ip(record.ip_subnet, 2),
                    "extintf": vl_inf[0],
                    #"extintf": 'any',
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
                #"extintf": self._fortigate["ext_interface"],
                "extintf": 'any',
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


def delete_vip(obj, context, floatingip_id):
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



def add_addrgrp(obj, context, **kwargs):
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
    cls = fortinet_db.Fortinet_Firewall_Address
    records = fortinet_db.query_records(context, cls, group=kwargs['name'])
    for name in kwargs['members']:
        record = fortinet_db.query_record(context, cls,
                                          name=name, vdom=kwargs['vdom'])
        if not record.group:
            record.update_record(context, record, group=kwargs['name'])
            # TODO: need to add a rollback action to taskmanager
        else:
            LOG.debug(_("The member %(record)s already joined a group"),
                      {"record": record})

    for record in records:
        kwargs['members'].append(record.name)

    try:
        op(obj, context, resources.FirewallAddrgrp.get,
           name=kwargs['name'], vdom=kwargs['vdom'])
        # TODO: need to add a rollback action to taskmanager
        op(obj, context, resources.FirewallAddrgrp.set, **kwargs)
    except exception.ResourceNotFound:
        op(obj, context, resources.FirewallAddrgrp.add, **kwargs)


def delete_addrgrp(obj, context, **kwargs):
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
    cls = fortinet_db.Fortinet_Firewall_Address
    records = fortinet_db.query_records(context, cls, group=kwargs["name"])
    if not records:
        LOG.debug(_("There is not any record in db"))
        return

    members = [record.name for record in records
                           if record.name not in kwargs['members']]
    if members:
        kwargs['members'] = members
        op(obj, context, resources.FirewallAddrgrp.set, **kwargs)
    else:
        try:
            op(obj, context, resources.FirewallPolicy.delete,
               vdom=kwargs.get('vdom'),
               srcintf='any',
               srcaddr=kwargs['name'],
               dstintf='any',
               nat='disable')
        except Exception as e:
            resources.Exinfo(e)
        try:
            del kwargs['members']
            op(obj, context, resources.FirewallAddrgrp.delete, **kwargs)
        except Exception as e:
            resources.Exinfo(e)
    for record in records:
        if record.name not in members:
            record.update_record(context, record, group=None)


def fortinet_add_vlink(obj, context, vdom):
    vlink_vlan = add_record(obj, context,
                        fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                        vdom=vdom)
    vlink_ip = add_record(obj, context,
                        fortinet_db.Fortinet_Vlink_IP_Allocation,
                        vdom=vdom,
                        vlan_id=vlink_vlan.vlan_id)
    if vlink_ip:
        ipsubnet = netaddr.IPNetwork(vlink_ip.vlink_ip_subnet)
        try:
            op(obj, context, resources.VlanInterface.get,
                     name=vlink_vlan.inf_name_ext_vdom,
                     vdom=const.EXT_VDOM)
        except exception.ResourceNotFound:
            op(obj, context, resources.VlanInterface.add,
                     name=vlink_vlan.inf_name_ext_vdom,
                     vdom=const.EXT_VDOM,
                     vlanid=vlink_vlan.vlan_id,
                     interface="npu0_vlink0",
                     ip=getip(ipsubnet, 1))
        try:
            op(obj, context, resources.VlanInterface.get,
                     name=vlink_vlan.inf_name_int_vdom,
                     vdom=vdom)

        except exception.ResourceNotFound:
            op(obj, context, resources.VlanInterface.add,
                     name=vlink_vlan.inf_name_int_vdom,
                     vdom=vdom,
                     vlanid=vlink_vlan.vlan_id,
                     interface="npu0_vlink1",
                     ip=getip(ipsubnet, 2))


def fortinet_delete_vlink(obj, context, tenant_id):
    vdom = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                   tenant_id=tenant_id).vdom
    vlink_vlan = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                            vdom=vdom,
                            allocated=True)
    if not vlink_vlan:
        return False

    vlink_ip = fortinet_db.query_record(context,
                              fortinet_db.Fortinet_Vlink_IP_Allocation,
                              vdom=vdom,
                              vlan_id=vlink_vlan.vlan_id,
                              allocated=True)
    if not vlink_ip:
        return False
    try:
        op(obj, context, resources.VlanInterface.delete,
                 name=vlink_vlan.inf_name_ext_vdom, vdom=const.EXT_VDOM)
    except exception.ResourceNotFound:
        LOG.exception(_("The vdom link %(vlink)s in the %(vdom)s "
                        "already was deleted.") %
                      ({'vlink': vlink_vlan.inf_name_ext_vdom,
                        'vdom':const.EXT_VDOM}))
    try:
        op(obj, context, resources.VlanInterface.delete,
                 name=vlink_vlan.inf_name_int_vdom, vdom=vdom)
    except exception.ResourceNotFound:
        LOG.debug(_("The vdom link %(vlink)s in the %(vdom)s "
                        "already was deleted.") %
                      ({'vlink': vlink_vlan.inf_name_ext_vdom,
                        'vdom':const.EXT_VDOM}))
    try:
        fortinet_db.delete_record(context,
                                  fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                                  vdom=vdom)
        fortinet_db.delete_record(context,
                                  fortinet_db.Fortinet_Vlink_IP_Allocation,
                                  vdom=vdom)
    except:
        LOG.debug(_("Failed to delete vlink"))
        raise Exception(_("Failed to delete vlink"))
    return True


def add_interface_ip(obj, context, **kwargs):
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
    inf_db = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_Interface,
                            name=kwargs.get('name'))
    if const.EXT_DEF_DST in getattr(inf_db, 'ip'):
        inf_db.update_record(context, inf_db, **kwargs)
        op(obj, context, resources.VlanInterface.set, **kwargs)
    else:
        records = fortinet_db.query_records(context,
                                  fortinet_db.Fortinet_Interface_subip,
                                  name=kwargs.get('name'))
        org_subips = [getattr(record, 'ip') for record in records]

        if kwargs.get('ip') in org_subips:
            return
        add_record(obj, context,
                   fortinet_db.Fortinet_Interface_subip, **kwargs)

        org_subips.append(kwargs.get('ip'))
        op(obj, context, resources.VlanInterface.set,
           name=kwargs.get('name'),
           vdom=kwargs.get('vdom'),
           secondaryips=org_subips)


def delete_interface_ip(obj, context, **kwargs):
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
    records = fortinet_db.query_records(context,
                                        fortinet_db.Fortinet_Interface_subip,
                                        name=kwargs.get('name'))
    org_subips = [getattr(record, 'ip') for record in records]
    if kwargs.get('ip') in org_subips:
        org_subips.remove(kwargs["ip"])
        op(obj, context, resources.VlanInterface.set,
           name=kwargs.get('name'),
           vdom=kwargs.get('vdom'),
           secondaryips=org_subips)
        fortinet_db.delete_record(context,
                                  fortinet_db.Fortinet_Interface_subip,
                                  **kwargs)
    else:
        inf_db = fortinet_db.query_record(context,
                                          fortinet_db.Fortinet_Interface,
                                          **kwargs)
        if not inf_db:
            return
        if org_subips:
            kwargs['ip'] = org_subips.pop()
            op(obj, context, resources.VlanInterface.set,
               name=kwargs.get('name'),
               vdom=kwargs.get('vdom'),
               secondaryips=org_subips)
            fortinet_db.delete_record(context,
                                  fortinet_db.Fortinet_Interface_subip,
                                  **kwargs)
        else:
            kwargs['ip'] = const.EXT_DEF_DST

        op(obj, context, resources.VlanInterface.set, **kwargs)
        inf_db.update_record(context, inf_db, ip=kwargs['ip'])


def set_ext_gw(obj, context, port):
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
    router_db = fortinet_db.query_record(context, l3_db.Router,
                                         id=port['device_id'])
    tenant_id = router_db.get('tenant_id', None)
    if not tenant_id:
        raise ValueError

    namespace = fortinet_add_vdom(obj, context, tenant_id=tenant_id)
    fortinet_add_vlink(obj, context, namespace.vdom)
    vlink_db = fortinet_db.query_record(context,
                                fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                                vdom=namespace.vdom)

    ip_address = port['fixed_ips'][0]['ip_address']
    add_fwippool(obj, context, vdom=const.EXT_VDOM,
                 name=ip_address, startip=ip_address)
    add_fwpolicy(obj, context,
                 vdom=const.EXT_VDOM,
                 srcintf=vlink_db.inf_name_ext_vdom,
                 dstintf=obj._fortigate['ext_interface'],
                 poolname=ip_address)
    subnet_db = fortinet_db.query_record(context, models_v2.Subnet,
                                id=port['fixed_ips'][0]['subnet_id'])
    if subnet_db:
        netmask = netaddr.IPNetwork(subnet_db.cidr).netmask
        add_interface_ip(obj, context,
                         name=obj._fortigate['ext_interface'],
                         vdom=const.EXT_VDOM,
                         ip="%s %s" % (ip_address, netmask))


def clr_ext_gw(obj, context, port):
    ip_address = port['fixed_ips'][0]['ip_address']
    delete_fwpolicy(obj, context, vdom=const.EXT_VDOM, poolname=ip_address)
    delete_fwippool(obj, context, vdom=const.EXT_VDOM, name=ip_address)
    subnetv2_db = fortinet_db.query_record(context, models_v2.Subnet,
                                    id=port['fixed_ips'][0]['subnet_id'])
    netmask = netaddr.IPNetwork(subnetv2_db.cidr).netmask
    ip = "%s %s" % (ip_address, netmask)
    delete_interface_ip(obj, context,
                        name=obj._fortigate['ext_interface'],
                        vdom=const.EXT_VDOM,
                        ip=ip)
