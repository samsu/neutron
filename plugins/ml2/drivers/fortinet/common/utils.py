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


def fortinet_add_vlink(cls, context, vdom, vlan_id, network_name):
    vlink_vlan = add_record(cls, context,
                        fortinet_db.Fortinet_Vlink_Vlan_Allocation,
                        vdom=vdom)
    vlink_ip = add_record(cls, context,
                        fortinet_db.Fortinet_Vlink_IP_Allocation,
                        vdom=vdom,
                        vlan_id=vlink_vlan.vlan_id)
    if vlink_ip:
        ipsubnet = netaddr.IPNetwork(vlink_ip.vlink_ip_subnet)
        try:
            op(cls, context, resources.VlanInterface.get,
                     name=vlink_vlan.inf_name_ext_vdom,
                     vdom=const.EXT_VDOM)
        except exception.ResourceNotFound:
            op(cls, context, resources.VlanInterface.add,
                     name=vlink_vlan.inf_name_ext_vdom,
                     vdom=const.EXT_VDOM,
                     vlanid=vlink_vlan.vlan_id,
                     interface="npu0_vlink0",
                     ip=getip(ipsubnet, 1))
        try:
            op(cls, context, resources.VlanInterface.get,
                     name=vlink_vlan.inf_name_int_vdom,
                     vdom=vdom)

        except exception.ResourceNotFound:
            op(cls, context, resources.VlanInterface.add,
                     name=vlink_vlan.inf_name_int_vdom,
                     vdom=vdom,
                     vlanid=vlink_vlan.vlan_id,
                     interface="npu0_vlink1",
                     ip=getip(ipsubnet, 2))

    inf_name = const.PREFIX["inf"] + str(vlan_id)
    try:
        op(cls, context, resources.VlanInterface.get,
                 name=inf_name, vdom=vdom)
    except exception.ResourceNotFound:
        op(cls, context, resources.VlanInterface.add,
                 name=inf_name,
                 vdom=vdom,
                 vlanid=vlan_id,
                 interface=cls._fortigate["int_interface"],
                 alias=network_name)


def fortinet_delete_vlink(cls, context, tenant_id):
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
        op(cls, context, resources.VlanInterface.delete,
                 name=vlink_vlan.inf_name_ext_vdom, vdom=const.EXT_VDOM)
    except exception.ResourceNotFound:
        LOG.exception(_("The vdom link %(vlink)s in the %(vdom)s "
                        "already was deleted.") %
                      ({'vlink': vlink_vlan.inf_name_ext_vdom,
                        'vdom':const.EXT_VDOM}))
    try:
        op(cls, context, resources.VlanInterface.delete,
                 name=vlink_vlan.inf_name_int_vdom, vdom=vdom)
    except exception.ResourceNotFound:
        LOG.debug(_("The vdom link %(vlink)s in the %(vdom)s "
                        "already was deleted.") %
                      ({'vlink': vlink_vlan.inf_name_ext_vdom,
                        'vdom':const.EXT_VDOM}))
    try:
        fortinet_db.Fortinet_Vlink_Vlan_Allocation.\
            delete_record(context, vdom=vdom)

        fortinet_db.Fortinet_Vlink_IP_Allocation.\
            delete_record(context, vdom=vdom)

    except:
        LOG.debug(_("Failed to delete vlink"))
        raise Exception(_("Failed to delete vlink"))
    return True