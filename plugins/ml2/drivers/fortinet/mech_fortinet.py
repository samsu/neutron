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
import sys
from oslo.config import cfg
from neutron.openstack.common import log as logging
from neutron.db import models_v2, l3_db
from neutron.db.external_net_db import ExternalNetwork
from neutron.db import api as db_api
from neutron.agent import securitygroups_rpc
from neutron.common import constants
from neutron.common import constants as l3_constants
from neutron.extensions import portbindings
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2.drivers.fortinet.db import models as fortinet_db
from neutron.plugins.ml2.drivers.fortinet.api_client import client
from neutron.plugins.ml2.drivers.fortinet.api_client import exception
from neutron.plugins.ml2.drivers.fortinet.common import constants as const
from neutron.plugins.ml2.drivers.fortinet.common import resources as resources
from neutron.plugins.ml2.drivers.fortinet.common import utils as utils
from neutron.plugins.ml2.drivers.fortinet.tasks import tasks
from neutron.plugins.ml2.drivers.fortinet.tasks import constants as t_consts


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
            'address': cfg.CONF.ml2_fortinet.address,
            'port': cfg.CONF.ml2_fortinet.port,
            'protocol': cfg.CONF.ml2_fortinet.protocol,
            'username': cfg.CONF.ml2_fortinet.username,
            'password': cfg.CONF.ml2_fortinet.password,
            'int_interface': cfg.CONF.ml2_fortinet.int_interface,
            'ext_interface': cfg.CONF.ml2_fortinet.ext_interface,
            'tenant_network_type': cfg.CONF.ml2_fortinet.tenant_network_type,
            'vlink_vlan_id_range': cfg.CONF.ml2_fortinet.vlink_vlan_id_range,
            'vlink_ip_range': cfg.CONF.ml2_fortinet.vlink_ip_range,
            'vip_mappedip_range': cfg.CONF.ml2_fortinet.vip_mappedip_range,
            'npu_available': cfg.CONF.ml2_fortinet.npu_available
        }

        api_server = [(self._fortigate['address'], self._fortigate['port'],
                      'https' == self._fortigate['protocol'])]
        self._driver = client.FortiosApiClient(api_server,
            self._fortigate['username'], self._fortigate['password'])

        for key in const.FORTINET_PARAMS:
            self.sync_conf_to_db(key)

        session = db_api.get_session()
        cls = fortinet_db.Fortinet_Interface
        ext_inf = {
            "name": self._fortigate['ext_interface'],
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
                           "name": self._fortigate['ext_interface'],
                           "vdom": const.EXT_VDOM
                }
                self._driver.request("SET_VLAN_INTERFACE", **message)

    def sync_conf_to_db(self, param):
        cls = getattr(fortinet_db, const.FORTINET_PARAMS[param]['cls'])
        conf_list = self.get_range(param)
        session = db_api.get_session()
        records = fortinet_db.query_records(session, cls)
        for record in records:
            kwargs = {}
            for key in const.FORTINET_PARAMS[param]['keys']:
                _element = const.FORTINET_PARAMS[param]['type'](record[key])
                if _element not in conf_list and not record.allocated:
                    kwargs.setdefault(key, record[key])
                    fortinet_db.delete_record(session, cls, **kwargs)
        try:
            for i in range(0, len(conf_list),
                           len(const.FORTINET_PARAMS[param]['keys'])):
                kwargs = {}
                for key in const.FORTINET_PARAMS[param]['keys']:
                    kwargs.setdefault(key, str(conf_list[i]))
                    i += 1
                cls.init_records(session, **kwargs)
        except IndexError:
            LOG.error(_("The number of the configure range is not even,"
                        "the last one of %(param)s can not be used"),
                      {'param': param})
            raise IndexError


    def get_range(self, param):
        _type = const.FORTINET_PARAMS[param]['type']
        if const.FORTINET_PARAMS[param]['format']:
            min, max = self._fortigate[param].split(const.FIELD_DELIMITER)
            if _type(min) > _type(max):
                min, max = max, min
            if _type == int:
                min, max =_type(min), _type(max) + 1
            result = const.FORTINET_PARAMS[param]['range'](min, max)
        else:
            result = const.FORTINET_PARAMS[param]['range'](
                                _type(self._fortigate[param]),
                                const.FORTINET_PARAMS[param]['netmask'])

        return result if isinstance(result, list) else list(result)


    def create_network_precommit(self, mech_context):
        """Create Network in the mechanism specific database table."""
        pass

    def create_network_postcommit(self, mech_context):
        """Create Network as a portprofile on the fortigate."""
        network = mech_context.current
        if network["router:external"]:
            # TODO
            return
        # use network_id to get the network attributes
        # ONLY depend on our db for getting back network attributes
        # this is so we can replay postcommit from db
        network_name = network['name']
        tenant_id = network['tenant_id']
        segment = mech_context.network_segments[0]
        # currently supports only one segment per network
        if segment['network_type'] != 'vlan':
            raise Exception(_("Fortinet Mechanism: failed to create network,"
                              "only network type vlan is supported"))

        vlanid = segment['segmentation_id']
        context = mech_context._plugin_context
        try:
            namespace = utils.add_vdom(self, context, tenant_id=tenant_id)
            if not namespace:
                raise
            # TODO: type driver support vlan only, need to check later
            inf_name = const.PREFIX['inf'] + str(vlanid)
            utils.add_vlanintf(self, context,
                               name=inf_name,
                               vdom=namespace.vdom,
                               vlanid=vlanid,
                               interface=self._fortigate['int_interface'],
                               alias=network_name)
        except Exception as e:
            utils._rollback_on_err(self, context, e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)


    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""
        network = mech_context.current
        network_id = network['id']
        context = mech_context._plugin_context
        if fortinet_db.query_record(context, ExternalNetwork,
                                    network_id=network_id):
            # return when the network is external network
            # TODO: may check external network before delete namespace
            return
        tenant_id = network['tenant_id']
        namespace = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                    tenant_id=tenant_id)
        if not namespace:
            return
        # TODO: type driver support vlan only, need to check later
        vlanid = network['provider:segmentation_id']
        inf_name = const.PREFIX['inf'] + str(vlanid)
        try:
            utils.delete_vlanintf(self, context, name=inf_name,
                     vdom=namespace.vdom)
        except Exception as e:
            resources.Exinfo(e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)

    def delete_network_postcommit(self, mech_context):
        """Delete network which translates to remove vlan interface
        and related vdom from the fortigate.
        """
        LOG.debug(_("delete_network_postcommit: called"))
        network = mech_context.current
        context = mech_context._plugin_context
        tenant_id = network['tenant_id']
        if not fortinet_db.query_count(context, models_v2.Network,
                                       tenant_id=tenant_id):
            try:
                namespace = fortinet_db.query_record(context,
                                    fortinet_db.Fortinet_ML2_Namespace,
                                    tenant_id=tenant_id)
                if not namespace:
                    return
                if not [ getattr(record, 'gw_port_id', None) for record
                         in fortinet_db.query_records(context,
                         l3_db.Router, tenant_id=namespace.tenant_id)
                         if getattr(record, 'gw_port_id', None)]:
                    utils.delete_vlink(self, context, tenant_id=tenant_id)
                    utils.delete_vdom(self, context, vdom=namespace.vdom)
                LOG.info(_("delete network postcommit: tenant= %(tenant_id)s"
                           " vdom= %(vdom)s"),
                          {'tenant_id': tenant_id,
                           'vdom': namespace.vdom})
            except Exception as e:
                resources.Exinfo(e)
                raise ml2_exc.MechanismDriverError(
                    method=sys._getframe().f_code.co_name)


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
        #LOG.debug(_("create_subnetwork_postcommit: called"))
        gateway = mech_context.current['gateway_ip']
        network_id = mech_context.current['network_id']
        subnet_id = mech_context.current['id']
        tenant_id = mech_context.current['tenant_id']
        context = mech_context._plugin_context
        try:
            if fortinet_db.query_record(context, ExternalNetwork,
                                        network_id=network_id):
                utils.add_routerstatic(self, context,
                                       subnet_id=subnet_id,
                                       vdom=const.EXT_VDOM,
                                       dst=const.EXT_DEF_DST,
                                       device=self._fortigate['ext_interface'],
                                       gateway=gateway)
            else:
                namespace = fortinet_db.query_record(context,
                                        fortinet_db.Fortinet_ML2_Namespace,
                                        tenant_id=tenant_id)
                interface = utils.get_intf(context,
                                           mech_context.current['network_id'])
                netmask = str(netaddr.\
                            IPNetwork(mech_context.current['cidr']).netmask)
                start_ip = mech_context.current['allocation_pools'][0]['start']
                end_ip = mech_context.current['allocation_pools'][0]['end']

                utils.add_dhcpserver(self, context,
                                     subnet_id=subnet_id,
                                     vdom=namespace.vdom,
                                     interface=interface,
                                     gateway=gateway,
                                     netmask=netmask,
                                     start_ip=start_ip,
                                     end_ip=end_ip)

                # TODO: need to add rollback for the update and set
                cls = fortinet_db.Fortinet_Interface
                record = fortinet_db.query_record(context, cls,
                                                  name=interface,
                                                  vdom=namespace.vdom)
                if gateway:
                    cls.update_record(context, record,
                                      ip="%s %s" % (gateway, netmask))
                    utils.op(self, context, resources.VlanInterface.set,
                             name=interface,
                             vdom=namespace.vdom,
                             ip="%s %s" % (gateway, netmask))
        except Exception as e:
            utils._rollback_on_err(self, context, e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)


    def delete_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("delete_subnetwork_precommit: called"))


    def delete_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        context = mech_context._plugin_context
        subnet_id = mech_context.current['id']
        try:
            utils.delete_routerstatic(self, context, subnet_id=subnet_id)
            utils.delete_dhcpserver(self, context, subnet_id=subnet_id)
        except Exception as e:
            resources.Exinfo(e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)


    def update_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""


    def update_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""


    def create_port_precommit(self, mech_context):
        """Create logical port on the fortigate (db update)."""
        port = mech_context.current
        LOG.debug(_("create_port_precommit mech_context = %s" % mech_context))
        context = mech_context._plugin_context
        namespace = fortinet_db.query_record(context,
                            fortinet_db.Fortinet_ML2_Namespace,
                            tenant_id=port['tenant_id'])
        port_id = port['id']
        subnet_id = port['fixed_ips'][0]['subnet_id']
        ip_address = port['fixed_ips'][0]['ip_address']
        mac = port['mac_address']
        db_subnetv2 = fortinet_db.query_record(context, models_v2.Subnet,
                                             id=subnet_id)
        if port['device_owner'] in ['network:router_gateway']:
            if fortinet_db.query_record(context, ExternalNetwork,
                                        network_id=port['network_id']):
                utils.set_ext_gw(self, context, port)
        elif port['device_owner'] in ['compute:nova', 'compute:None', '']:
            # add dhcp related functions
            # '': create port before associate the port with a vm
            utils.add_reservedip(self, context,
                                 port_id=port_id,
                                 subnet_id=subnet_id,
                                 mac=mac,
                                 ip=ip_address,
                                 vdom=namespace.vdom)

        elif port['device_owner'] in ['network:router_interface']:
            if db_subnetv2.cidr:
                cidr = netaddr.IPNetwork(db_subnetv2.cidr)
                subnet = ' '.join([str(cidr.network), str(cidr.netmask)])
                utils.add_fwaddress(self, context,
                                   vdom=namespace.vdom,
                                   name=str(cidr.network),
                                   subnet=subnet)
                addrgrp_name = const.PREFIX['addrgrp'] + namespace.vdom
                utils.add_addrgrp(self, context,
                                  name=addrgrp_name,
                                  vdom=namespace.vdom,
                                  members=[str(cidr.network),])

                utils.add_fwpolicy(self, context,
                                   vdom=namespace.vdom,
                                   srcintf='any',
                                   srcaddr=addrgrp_name,
                                   dstintf='any',
                                   dstaddr=addrgrp_name,
                                   nat='disable')
        return


    def create_port_postcommit(self, mech_context):
        """Associate the assigned MAC address to the portprofile."""
        context = mech_context._plugin_context
        utils.update_status(self, context, t_consts.TaskStatus.COMPLETED)


    def delete_port_postcommit(self, mech_context):
        port = mech_context.current
        context = mech_context._plugin_context
        try:
            port_id = port['id']
            subnet_id = port['fixed_ips'][0]['subnet_id']
            db_subnet = fortinet_db.query_record(context,
                                             fortinet_db.Fortinet_ML2_Subnet,
                                             subnet_id=subnet_id)
            db_subnetv2 = fortinet_db.query_record(context, models_v2.Subnet,
                                                   id=subnet_id)
            if port['device_owner'] in ['network:router_gateway']:
                if fortinet_db.query_record(context, ExternalNetwork,
                                            network_id=port['network_id']):
                    #delete ippool and its related firewall policy
                    utils.clr_ext_gw(self, context, port)

            elif port['device_owner'] in ['compute:nova', 'compute:None', '']:
                # delete dhcp related functions
                utils.delete_reservedip(self, context, port_id=port_id)

            elif port['device_owner'] in ['network:router_interface']:
                # add firewall address and address group
                name = const.PREFIX['addrgrp'] + db_subnet.vdom
                member = str(netaddr.IPNetwork(db_subnetv2.cidr).network)
                utils.delete_fwpolicy(self, context,
                                   vdom=db_subnet.vdom,
                                   srcintf='any',
                                   srcaddr=name,
                                   dstintf='any',
                                   dstaddr=name,
                                   nat='disable')
                utils.delete_addrgrp(self, context,
                                     name=name,
                                     vdom=db_subnet.vdom,
                                     members=member.split(' '))
                utils.delete_fwaddress(self, context,
                                   vdom=db_subnet.vdom,
                                   name=member)
        except Exception as e:
            resources.Exinfo(e)
            raise ml2_exc.MechanismDriverError(
                method=sys._getframe().f_code.co_name)


    def update_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""


    def update_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""


    def bind_port(self, context):
        """Marks ports as bound.

        Binds external ports and ports.
        Fabric configuration will occur on the subsequent port update.
        Currently only vlan segments are supported.
        """
        LOG.debug(_("bind_port() called"))
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
