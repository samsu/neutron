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


def fortinet_add_vdom(obj, context, **kwargs):
    namespace = add_record(obj, context, fortinet_db.Fortinet_ML2_Namespace,
                           **kwargs)
    try:
        op(obj, context, resources.Vdom.get, name=namespace.vdom)
    except exception.ResourceNotFound:
        op(obj, context, resources.Vdom.add, name=namespace.vdom)
    return namespace


def add_fwippool(obj, context, **kwargs):
    record = add_record(obj, context,
                        fortinet_db.Fortinet_Firewall_IPPool, **kwargs)
    try:
        op(obj, context, resources.FirewallIppool.get,
           vdom=record.vdom, name=record.name)
    except exception.ResourceNotFound:
        op(obj, context, resources.FirewallIppool.add, **kwargs)
    return record

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

def add_resource(obj, context, cls, resource, **kwargs):
    #cls = fortinet_db.Fortinet_Firewall_Address
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
    for name in kwargs['members']:
        record = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_Firewall_Address,
                                    name=name,
                                    vdom=kwargs['vdom'])
        if not record.group:
            record.update_record(context, record, group=kwargs['name'])
            # TODO: need to add a rollback action to taskmanager
        else:
            LOG.debug(_("The member %(record)s already joined a group"),
                      {"record": record})
    try:
        op(obj, context, resources.FirewallAddrgrp.get,
           name=kwargs['name'], vdom=kwargs['vdom'])
        # TODO: need to add a rollback action to taskmanager
        op(obj, context, resources.FirewallAddrgrp.set, **kwargs)
    except exception.ResourceNotFound:
        op(obj, context, resources.FirewallAddrgrp.add, **kwargs)



def add_member_addrgrp(obj, context, **kwargs):
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

    cls = fortinet_db.Fortinet_Firewall_Address
    if not kwargs.get("members", None) and not kwargs.get("name", None):
        LOG.debug(_("### there is no member and no group name"))
        return

    records = fortinet_db.query_records(context,
                                        fortinet_db.Fortinet_Firewall_Address,
                                        group=kwargs['name'])
    #records = fortinet_db.get_records(session, cls, group=kwargs["name"])

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
