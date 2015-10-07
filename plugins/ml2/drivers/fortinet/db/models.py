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


"""Fortinet specific database schema/model."""

import sqlalchemy as sa
import neutron.plugins.ml2.db as ml2_db
from oslo.db import exception as os_db_exception

from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import l3_db
from neutron.db.external_net_db import ExternalNetwork
## TODO: add log here temporarily
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.fortinet.common import constants as const


LOG = logging.getLogger(__name__)


OPS = ["ADD", "UPDATE", "DELETE", "QUERY"]
class DBbase(object):
    @classmethod
    def add(cls, context, kwargs):
        """Add vlanid to be allocated into the table"""
        session = context.session
        with session.begin(subtransactions=True):
            record = cls.query(context, kwargs)
            LOG.debug(_("##### add_record() record = %s" % record))
            if not record:
                record = cls()
                for key, value in kwargs.iteritems():
                    if hasattr(record, key):
                        setattr(record, key, value)
                print "record = ", record
                #import ipdb; ipdb.set_trace()
                session.add(record)
            else:
                raise os_db_exception.DBDuplicateEntry
        return record

    @classmethod
    def update(context, record, kwargs):
        """Add vlanid to be allocated into the table"""
        try:
            session = context.session
            for key, value in kwargs.iteritems():
                if hasattr(record, key):
                    setattr(record, key, value)
            with session.begin(subtransactions=True):
                session.add(record)
        except Exception as ex:
            raise os_db_exception.DBError

    @classmethod
    def delete(cls, context, kwargs):
        """Delete vlanid to be allocated into the table"""
        session = context.session
        with session.begin(subtransactions=True):
            record = cls.query(context, kwargs)
            if record:
                session.delete(record)
        return record

    @classmethod
    def query(cls, context, kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        session = context.session
        print "query() cls = %s" % cls
        print "query() kwargs = %s" % kwargs
        query = cls._query(session, **kwargs)
        return query.first()

    @classmethod
    def query_all(cls, context, kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        session = context.session
        query = cls._query(session, **kwargs)
        return query.all()

    @classmethod
    def _query(cls, session, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        if not hasattr(session, "query"):
            #LOG.debug(_("##### not attr query? session = %s" % session))
            session = session.session
        LOG.debug(_("##### kwargs = %s" % kwargs))
        query = session.query(cls)
        for key, value in kwargs.iteritems():
            #LOG.debug(_("##### key = %s, value =%s" % (key, value)))
            kw = {key: value}
            query = query.filter_by(**kw)
            #LOG.debug(_("##### query = %s" % query))
        return query

class Fortinet_ML2_Namespace(model_base.BASEV2):
    """Schema for Fortinet network."""
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    tenant_id = sa.Column(sa.String(36), primary_key=True)
    # For the name of vdom has the following restrictions:
    # only letters, numbers, "-" and "_" are allowed
    # no more than 11 characters are allowed
    # no spaces are allowed
    vdom = sa.Column(sa.String(11))

class Fortinet_ML2_Subnet(model_base.BASEV2):
    """Schema to map subnet to Fortinet dhcp interface."""
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    subnet_id = sa.Column(sa.String(36))
    vdom = sa.Column(sa.String(11))
    mkey = sa.Column(sa.Integer)

class Fortinet_ML2_ReservedIP(model_base.BASEV2):
    """Schema for Fortinet dhcp server reserved ip."""
    port_id = sa.Column(sa.String(36), primary_key=True)
    subnet_id = sa.Column(sa.String(36))
    mac = sa.Column(sa.String(32))
    ip = sa.Column(sa.String(32))
    vdom = sa.Column(sa.String(11))
    edit_id = sa.Column(sa.Integer)

class Fortinet_Static_Router(model_base.BASEV2, DBbase):
    """Schema for Fortinet static router."""
    subnet_id = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    edit_id = sa.Column(sa.Integer)

class Fortinet_Vlink_Vlan_Allocation(model_base.BASEV2):
    """Schema for Fortinet vlink vlan interface."""
    vlan_id = sa.Column(sa.Integer, primary_key=True)
    vdom = sa.Column(sa.String(11))
    inf_name_int_vdom = sa.Column(sa.String(11))
    inf_name_ext_vdom = sa.Column(sa.String(11))
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)

class Fortinet_Vlink_IP_Allocation(model_base.BASEV2):
    """Schema for Fortinet vlink vlan interface."""
    vlink_ip_subnet = sa.Column(sa.String(32), primary_key=True)
    vdom = sa.Column(sa.String(11))
    vlan_id = sa.Column(sa.Integer)
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)


class Fortinet_Firewall_Policy(model_base.BASEV2):
    """Schema for Fortinet firewall policy."""
    __tablename__ = 'fortinet_firewall_policies'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    vdom = sa.Column(sa.String(11))
    srcintf = sa.Column(sa.String(11))
    dstintf = sa.Column(sa.String(11))
    srcaddr = sa.Column(sa.String(32), default="all")
    dstaddr = sa.Column(sa.String(32), default="all")
    poolname = sa.Column(sa.String(32), default=None)
    nat = sa.Column(sa.String(7), default="disable")
    edit_id = sa.Column(sa.Integer)


class Fortinet_FloatingIP_Allocation(model_base.BASEV2):
    """Schema for Fortinet vlink vlan interface.
    ip_subnet: it is a network with 30 bits network, there
    are two ips available, the smaller one will be allocated
    to the interface of the external network vdom and the
    bigger one will be allocated to the interface of related
    tenant network vdom.
    """
    ip_subnet = sa.Column(sa.String(32), primary_key=True)
    floating_ip_address = sa.Column(sa.String(36))
    vdom = sa.Column(sa.String(11))
    vip_name = sa.Column(sa.String(50))
    ## secondary_ip = sa.Column(sa.String(50), default=None)
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)
    bound = sa.Column(sa.Boolean(), default=False, nullable=False)


class Fortinet_Firewall_IPPool(model_base.BASEV2):
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    startip = sa.Column(sa.String(32))
    endip = sa.Column(sa.String(32))
    type = sa.Column(sa.String(32), default="one-to-one")
    comments = sa.Column(sa.String(32), default=None)


class Fortinet_Firewall_Address(model_base.BASEV2):
    __tablename__ = 'fortinet_firewall_addresses'
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    subnet = sa.Column(sa.String(32))
    associated_interface = sa.Column(sa.String(11), default=None)
    group = sa.Column(sa.String(32), default=None)


class Fortinet_Interface(model_base.BASEV2):
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    vlan_id = sa.Column(sa.Integer)
    interface = sa.Column(sa.String(11), default=None)
    type = sa.Column(sa.String(32),default=None)
    ip = sa.Column(sa.String(32), default="0.0.0.0 0.0.0.0")
    secondary_ip = sa.Column(sa.String(11), default="enable")
    alias = sa.Column(sa.String(32), default=None)


class Fortinet_Interface_subip(model_base.BASEV2):
    ip = sa.Column(sa.String(32), primary_key=True)
    name = sa.Column(sa.String(11), default=None)
    vdom = sa.Column(sa.String(11))

class ML2_FortinetPort(model_base.BASEV2, models_v2.HasId,
                      models_v2.HasTenant):
    """Schema for Fortinet port."""
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("ml2_Fortinetnetworks.id"),
                           nullable=False)
    admin_state_up = sa.Column(sa.Boolean, nullable=False)
    physical_interface = sa.Column(sa.String(36))
    vlan_id = sa.Column(sa.String(36))


def add_record(session, cls, **kwargs):
    """Add vlanid to be allocated into the table"""
    ##session = context.session
    with session.begin(subtransactions=True):
        record = get_record(session, cls, **kwargs)
        LOG.debug(_("##### add_record() record = %s" % record))
        if not record:
            record = cls()
            for key, value in kwargs.iteritems():
                if hasattr(record, 'key'):
                    setattr(record, key, value)
            session.add(record)
    return record


def update_record(context, record, **kwargs):
    """Add vlanid to be allocated into the table"""
    try:
        for key, value in kwargs.iteritems():
            if hasattr(record, 'key'):
                setattr(record, key, value)
        session = context.session
        with session.begin(subtransactions=True):
            session.add(record)
    except Exception as ex:
        raise os_db_exception.DBError


def delete_record(session, cls, **kwargs):
    """Delete vlanid to be allocated into the table"""
    with session.begin(subtransactions=True):
        record = get_record(session, cls, **kwargs)
        if record:
            session.delete(record)
    return record


def get_record(session, cls, **kwargs):
    """Get a filtered vlink_vlan_allocation record."""
    #session = context.session
    query = _query(session, cls, **kwargs)
    return query.first()


def get_records(session, cls, **kwargs):
    """Get a filtered vlink_vlan_allocation record."""
    query = _query(session, cls, **kwargs)
    return query.all()


def _query(session, cls, **kwargs):
    """Get a filtered vlink_vlan_allocation record."""
    if not hasattr(session, "query"):
        #LOG.debug(_("##### not attr query? session = %s" % session))
        session = session.session
    LOG.debug(_("##### kwargs = %s" % kwargs))
    query = session.query(cls)
    for key, value in kwargs.iteritems():
        #LOG.debug(_("##### key = %s, value =%s" % (key, value)))
        kw = {key: value}
        query = query.filter_by(**kw)
        #LOG.debug(_("##### query = %s" % query))
    return query


def create_namespace(context, tenant_id):
    """Create a Fortinet vdom associated with the Tenant."""
    session = context.session
    with session.begin(subtransactions=True):
        namespace = get_namespace(context, tenant_id)
        if not namespace:
            namespace = Fortinet_ML2_Namespace(tenant_id=tenant_id,
                                               vdom=None)
            session.add(namespace)
            id = get_namespace(context, tenant_id)["id"]
            vdom = const.PREFIX["vdom"] + str(id)
            namespace.vdom = vdom
            session.add(namespace)
    return namespace


def delete_namespace(context, tenant_id):
    """Create a Fortinet vdom associated with the Tenant."""
    session = context.session
    with session.begin(subtransactions=True):
        namespace = get_namespace(context, tenant_id)
        session.delete(namespace)
    return namespace

def get_namespace(context, tenant_id):
    """Get Fortinet specific vdom name associated with a tenant."""
    session = context.session
    namespace = session.query(Fortinet_ML2_Namespace).\
        filter_by(tenant_id=tenant_id).first()
    return namespace

def tenant_network_count(context, tenant_id):
    session = context.session
    with session.begin(subtransactions=True):
        return session.query(models_v2.Network).\
                     filter_by(tenant_id=tenant_id).count()

def get_ext_network(context, network_id):
    """Get Fortinet specific network, with vlan extension."""
    session = context.session
    return session.query(ExternalNetwork).\
                   filter_by(network_id=network_id).first()


def create_network(context, net_id, vlan, segment_id, network_type, tenant_id):
    """Create a Fortinet specific network/port-profiles."""

    # only network_type of vlan is supported
    session = context.session
    with session.begin(subtransactions=True):
        net = get_network(context, net_id, None)
        if not net:
            net = ML2_FortinetNetwork(id=net_id, vlan=vlan,
                                     segment_id=segment_id,
                                     network_type='vlan',
                                     tenant_id=tenant_id)
            session.add(net)
    return net


def delete_network(context, net_id):
    """Delete a Fortinet specific network/port-profiles."""

    session = context.session
    with session.begin(subtransactions=True):
        net = get_network(context, net_id, None)
        if net:
            session.delete(net)

def get_network(context, net_id, fields=None):
    """Get Fortinet specific network, with vlan extension."""
    session = context.session
    return session.query(ML2_FortinetNetwork).filter_by(id=net_id).first()


def get_interface_subips(context, name):
    """
    name: the interface name, e.g. port32
    """
    session = context.session
    records = session.query(Fortinet_Interface_subip).\
                    filter_by(name=name).all()
    if records:
        return [record.ip for record in records]
    return []

def get_networks(context, filters=None, fields=None):
    """Get all Fortinet specific networks."""
    session = context.session
    return session.query(ML2_FortinetNetwork).all()

def get_vdom(context, subnet_id):
    session = context.session
    subnet = session.query(models_v2.Subnet).\
                     filter_by(id=subnet_id).first()
    if subnet:
        namespace = get_namespace(context, subnet.tenant_id)
        return namespace.vdom
    return None

def create_subnet(context, subnet_id, mkey=None):
    """Create a subnet associated with a fortigate's dhcp server"""
    session = context.session
    with session.begin(subtransactions=True):
        subnet = get_subnet(context, subnet_id)
        if not subnet:
            vdom = get_vdom(context, subnet_id)
            subnet = Fortinet_ML2_Subnet(subnet_id=subnet_id,
                                         vdom=vdom,
                                         mkey=mkey)
            session.add(subnet)
    return subnet

def delete_subnet(context, subnet_id):
    """Delete a subnet associated with a fortigate's dhcp server"""
    session = context.session
    with session.begin(subtransactions=True):
        subnet = get_subnet(context, subnet_id)
        if subnet:
            session.delete(subnet)
    return subnet

def update_subnet(context, subnet_id, mkey):
    """Create a Fortinet vdom associated with the Tenant."""
    session = context.session
    with session.begin(subtransactions=True):
        subnet = get_subnet(context, subnet_id)
        subnet.mkey = mkey
        session.add(subnet)
    return subnet

def get_subnet(context, subnet_id):
    session = context.session
    subnet = session.query(Fortinet_ML2_Subnet).\
             filter_by(subnet_id=subnet_id).first()
    return subnet

def get_subnets(context, vdom):
    session = context.session
    subnets = session.query(Fortinet_ML2_Subnet).\
             filter_by(vdom=vdom).all()
    return subnets

def create_reserved_ip(context, port_id, subnet_id, tenant_id,
                       ip, mac, edit_id=None):
    """associated vm's ip and vm's mac with the related dhcp server"""
    session = context.session
    with session.begin(subtransactions=True):
        reserved_ip = get_reserved_ip(context, port_id)
        if not reserved_ip:
            namespace = get_namespace(context, tenant_id)
            vdom = namespace.vdom
            _last_record = session.query(Fortinet_ML2_ReservedIP).\
                filter_by(subnet_id=subnet_id).\
                order_by(Fortinet_ML2_ReservedIP.edit_id.desc()).first()
            edit_id = _last_record.edit_id + 1 if _last_record else 1
            reserved_ip = Fortinet_ML2_ReservedIP(port_id=port_id,
                                                  subnet_id=subnet_id,
                                                  mac=mac,
                                                  ip=ip,
                                                  vdom=vdom,
                                                  edit_id=edit_id)
            session.add(reserved_ip)
    return reserved_ip

def update_reserved_ip(context, port_id, edit_id=None):
    """update the edit_id of the record with id = port_id"""
    session = context.session
    with session.begin(subtransactions=True):
        reserved_ip = get_reserved_ip(context, port_id)
        if reserved_ip and edit_id:
            reserved_ip.edit_id = edit_id
            session.add(reserved_ip)
            return reserved_ip
        else:
            return None


def get_reserved_ip(context, port_id):
    session = context.session
    reserved_ip = session.query(Fortinet_ML2_ReservedIP).\
                  filter_by(port_id=port_id).first()
    return reserved_ip

def get_reserved_ips(context, subnet_id):
    session = context.session
    reserved_ips = session.query(Fortinet_ML2_ReservedIP).\
                  filter_by(subnet_id=subnet_id).all()
    LOG.debug(_("!!!!! reserved_ips = %s" % reserved_ips))
    return reserved_ips

def delete_reserved_ip(context, port_id):
    """delete the record from the table Fortinet_ML2_ReservedIP"""
    session = context.session
    with session.begin(subtransactions=True):
        reserved_ip = get_reserved_ip(context, port_id)
        if reserved_ip:
            session.delete(reserved_ip)
    return reserved_ip


def create_static_router(context, subnet_id, vdom, edit_id=None):
    """add static router records to the table fortinet_static_routers"""
    session = context.session
    with session.begin(subtransactions=True):
        static_router = get_static_router(context, subnet_id)
        if not static_router:
            static_router = Fortinet_Static_Router(subnet_id=subnet_id,
                                                  vdom=vdom,
                                                  edit_id=edit_id)
            session.add(static_router)
    return static_router

def get_static_router(context, subnet_id):
    """query static router records of the table fortinet_static_routers"""
    session = context.session
    with session.begin(subtransactions=True):
        static_router = session.query(Fortinet_Static_Router).\
                  filter_by(subnet_id=subnet_id).first()
    return static_router

def delete_static_router(context, subnet_id):
    """delete a static router record from the table fortinet_static_routers"""
    session = context.session
    with session.begin(subtransactions=True):
        static_router = session.query(Fortinet_Static_Router).\
                  filter_by(subnet_id=subnet_id).first()
        if static_router:
            session.delete(static_router)
    return static_router


def get_secondaryips(context, subnet_id):
    session = context.session
    with session.begin(subtransactions=True):
        static_router = session.query(Fortinet_FloatingIP_Allocation).\
                  filter_by(subnet_id=subnet_id).all()
        if static_router:
            session.delete(static_router)
    return secondaryips


def create_port(context, port_id, network_id, physical_interface,
                vlan_id, tenant_id, admin_state_up):
    """Create a Fortinet specific port, has policy like vlan."""

    session = context.session
    with session.begin(subtransactions=True):
        port = get_port(context, port_id)
        if not port:
            port = ML2_FortinetPort(id=port_id,
                                   network_id=network_id,
                                   physical_interface=physical_interface,
                                   vlan_id=vlan_id,
                                   admin_state_up=admin_state_up,
                                   tenant_id=tenant_id)
            session.add(port)
    return port


def get_port(context, port_id):
    """get a Fortinet specific port."""
    session = context.session
    return session.query(ML2_FortinetPort).filter_by(id=port_id).first()


def get_ports(context, network_id=None):
    """get a Fortinet specific port."""

    session = context.session
    return session.query(ML2_FortinetPort).filter_by(
        network_id=network_id).all()


def delete_port(context, port_id):
    """delete Fortinet specific port."""

    session = context.session
    with session.begin(subtransactions=True):
        port = get_port(context, port_id)
        if port:
            session.delete(port)


def update_port_state(context, port_id, admin_state_up):
    """Update port attributes."""
    session = context.session
    with session.begin(subtransactions=True):
        session.query(ML2_FortinetPort).filter_by(
            id=port_id).update({'admin_state_up': admin_state_up})

def get_router(context, id):
    session = context.session
    with session.begin(subtransactions=True):
        return session.query(l3_db.Router).filter_by(id=id).first()

