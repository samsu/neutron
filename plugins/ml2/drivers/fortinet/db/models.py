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

def add_record(context, cls, **kwargs):
    try:
        return cls.add_record(context, **kwargs)
    except os_db_exception.DBDuplicateEntry:
        pass
    return {}

def delete_record(context, cls, **kwargs):
    return cls.delete_record(context, kwargs)

def query_record(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).first()

def query_records(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).all()

def query_count(context, cls, **kwargs):
    return db_query(cls, context, **kwargs).count()

def get_session(context):
    return context.session if hasattr(context, "session") else context

def db_query(cls, context, **kwargs):
    """Get a filtered vlink_vlan_allocation record."""
    session = get_session(context)
    LOG.debug(_("##### kwargs = %s" % kwargs))
    query = session.query(cls)
    for key, value in kwargs.iteritems():
        kw = {key: value}
        query = query.filter_by(**kw)
    return query


class DBbase(object):
    @classmethod
    def add_record(cls, context, **kwargs):
        """Add vlanid to be allocated into the table"""
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query(context, **kwargs)
            if not record:
                record = cls()
                for key, value in kwargs.iteritems():
                    if hasattr(record, key):
                        setattr(record, key, value)
                session.add(record)
                rollback = record._prepare_rollback(context,
                                                    cls.delete_record,
                                                    **kwargs)
            else:
                rollback = {}
                #raise os_db_exception.DBDuplicateEntry
        ## TODO: kwargs would be better if only include class cls
        ## related primary keys
        return {'result': record, 'rollback': rollback}

    @staticmethod
    def update_record(context, record, **kwargs):
        """Add vlanid to be allocated into the table"""
        session = get_session(context)
        try:
            for key, value in kwargs.iteritems():
                if hasattr(record, key):
                    setattr(record, key, value)
            with session.begin(subtransactions=True):
                session.add(record)
        except Exception as e:
            raise os_db_exception.DBError

    @classmethod
    def delete_record(cls, context, kwargs):
        """
        Delete the record with the value of kwargs from the database,
        kwargs is a dictionary variable, here should not pass into a
        variable like **kwargs
        """
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query(context, **kwargs)
            if record:
                session.delete(record)
        return record

    @classmethod
    def query(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        session = get_session(context)
        query = db_query(cls, session, **kwargs)
        return query.first()

    @classmethod
    def query_all(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        session = get_session(context)
        query = db_query(cls, session, **kwargs)
        return query.all()

    @classmethod
    def query_count(cls, context, **kwargs):
        """Get a filtered vlink_vlan_allocation record."""
        session = get_session(context)
        query = db_query(cls, session, **kwargs)
        return query.count()

    def _prepare_rollback(self, context, func, **kwargs):
        if not func:
            raise ValueError
        rollback = {
            'func': func,
            'params': (context, kwargs)
        }
        return rollback

class Fortinet_ML2_Namespace(model_base.BASEV2, DBbase):
    """Schema for Fortinet network."""
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    tenant_id = sa.Column(sa.String(36), primary_key=True)
    # For the name of vdom has the following restrictions:
    # only letters, numbers, "-" and "_" are allowed
    # no more than 11 characters are allowed
    # no spaces are allowed
    vdom = sa.Column(sa.String(11))

    @classmethod
    def add_record(cls, context, **kwargs):
        #import ipdb;ipdb.set_trace()
        res = super(Fortinet_ML2_Namespace, cls).add_record(context, **kwargs)
        if res.get('rollback'):
            res['result']._allocate_vdom(context, res['result'])
        return res

    def _allocate_vdom(self, context, record):
        if not getattr(record, 'vdom'):
            vdom = const.PREFIX['vdom'] + str(record.id)
            self.update_record(context, record, vdom=vdom)
            print "## query result: %s", self.query(context, vdom=vdom)
        return record.vdom

class Fortinet_ML2_Subnet(model_base.BASEV2, DBbase):
    """Schema to map subnet to Fortinet dhcp interface."""
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    subnet_id = sa.Column(sa.String(36))
    vdom = sa.Column(sa.String(11))
    mkey = sa.Column(sa.Integer)

class Fortinet_ML2_ReservedIP(model_base.BASEV2, DBbase):
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

class Fortinet_Vlink_Vlan_Allocation(model_base.BASEV2, DBbase):
    """Schema for Fortinet vlink vlan interface."""
    vlan_id = sa.Column(sa.Integer, primary_key=True)
    vdom = sa.Column(sa.String(11))
    inf_name_int_vdom = sa.Column(sa.String(11))
    inf_name_ext_vdom = sa.Column(sa.String(11))
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)

    @staticmethod
    def reset():
        """
        set all value of keys in kwargs to the default value(None or False)
        """
        return {
            'vdom': None,
            'inf_name_int_vdom': None,
            'inf_name_ext_vdom': None,
            'allocated': False
        }

    @classmethod
    def add_record(cls, context, **kwargs):
        session = get_session(context)
        #with session.begin(subtransactions=True):
        record = cls.query(context, **kwargs)
        if not record:
            record = cls.query(context, allocated=False)
            kwargs.setdefault('allocated', True)
            kwargs.setdefault('inf_name_int_vdom', const.PREFIX["vint"] + \
                                   str(record.vlan_id))
            kwargs.setdefault('inf_name_ext_vdom', const.PREFIX["vext"] + \
                                   str(record.vlan_id))
            cls.update_record(context, record, **kwargs)
            rollback = record._prepare_rollback(context, cls.delete_record,
                                             **kwargs)
        else:
            rollback = {}
        ## need to check the attribute in the record whether updated
        ## # after update_record()
        return {'result': record, 'rollback': rollback}


    @classmethod
    def delete_record(cls, context, kwargs):
        """Delete vlanid to be allocated into the table"""
        session = get_session(context)
        #with session.begin(subtransactions=True):
        record = cls.query(context, **kwargs)
        if record:
            cls.update(context, record, cls.reset())
        return record


class Fortinet_Vlink_IP_Allocation(model_base.BASEV2, DBbase):
    """Schema for Fortinet vlink vlan interface."""
    vlink_ip_subnet = sa.Column(sa.String(32), primary_key=True)
    vdom = sa.Column(sa.String(11))
    vlan_id = sa.Column(sa.Integer)
    allocated = sa.Column(sa.Boolean(), default=False, nullable=False)

    @staticmethod
    def reset():
        """
        set all value of keys in kwargs to the default value(None or False)
        """
        return {
            'vdom': None,
            'vlan_id': None,
            'allocated': False
        }

    @classmethod
    def add_record(cls, context, **kwargs):
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query(context, **kwargs)
            if not record:
                record = cls.query(context, allocated=False)
                kwargs.setdefault('allocated', True)
                cls.update_record(context, record, **kwargs)
                rollback = record._prepare_rollback(context,
                                                    cls.delete_record,
                                                    **kwargs)
            else:
                rollback = {}
        ## need to check the attribute in the record whether updated
        ## # after update_record()
        return {'result': record, 'rollback': rollback}


    @classmethod
    def delete_record(cls, context, kwargs):
        """Delete vlanid to be allocated into the table"""
        session = get_session(context)
        with session.begin(subtransactions=True):
            record = cls.query(context, **kwargs)
            if record:
                record.update(context, record, cls.reset())
        return record


class Fortinet_Firewall_Policy(model_base.BASEV2, DBbase):
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


class Fortinet_FloatingIP_Allocation(model_base.BASEV2, DBbase):
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


class Fortinet_Firewall_IPPool(model_base.BASEV2, DBbase):
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    startip = sa.Column(sa.String(32))
    endip = sa.Column(sa.String(32))
    type = sa.Column(sa.String(32), default="one-to-one")
    comments = sa.Column(sa.String(32), default=None)


class Fortinet_Firewall_Address(model_base.BASEV2, DBbase):
    __tablename__ = 'fortinet_firewall_addresses'
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11), primary_key=True)
    subnet = sa.Column(sa.String(32))
    associated_interface = sa.Column(sa.String(11), default=None)
    group = sa.Column(sa.String(32), default=None)


class Fortinet_Interface(model_base.BASEV2, DBbase):
    name = sa.Column(sa.String(36), primary_key=True)
    vdom = sa.Column(sa.String(11))
    vlan_id = sa.Column(sa.Integer)
    interface = sa.Column(sa.String(11), default=None)
    type = sa.Column(sa.String(32),default=None)
    ip = sa.Column(sa.String(32), default="0.0.0.0 0.0.0.0")
    secondary_ip = sa.Column(sa.String(11), default="enable")
    alias = sa.Column(sa.String(32), default=None)


class Fortinet_Interface_subip(model_base.BASEV2, DBbase):
    ip = sa.Column(sa.String(32), primary_key=True)
    name = sa.Column(sa.String(11), default=None)
    vdom = sa.Column(sa.String(11))


class ML2_FortinetPort(model_base.BASEV2, models_v2.HasId,
                      models_v2.HasTenant, DBbase):
    """Schema for Fortinet port."""
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("ml2_Fortinetnetworks.id"),
                           nullable=False)
    admin_state_up = sa.Column(sa.Boolean, nullable=False)
    physical_interface = sa.Column(sa.String(36))
    vlan_id = sa.Column(sa.String(36))

