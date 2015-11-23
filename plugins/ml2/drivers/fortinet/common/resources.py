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

import re
import sys
import os
from types import MethodType
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.fortinet.api_client import exception as api_ex
from neutron.plugins.ml2.drivers.fortinet.common import constants as const

# For debug purpose
def funcinfo():
     import inspect
     cur_func = inspect.stack()[1][3]
     caller = inspect.stack()[2][3]
     print "### current function is %s(), its caller is %s()" % \
           (cur_func, caller)
     LOG.debug(_("## current function is %s, its caller is %s"
                 % (cur_func, caller)))

LOG = logging.getLogger(__name__)

OPS = ["ADD", "DELETE", "SET", "GET", "MOVE"]
RB_FUNC = {'add': 'delete'}

class Exinfo(object):
    def __init__(self, exception):
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        LOG.error(_("An exception of type %(exception)s occured with arguments"
                    " %(args)s, line %(line)s, in %(file)s"),
                    {'exception': type(exception).__name__,
                     'args': exception.args,
                     'line':exc_tb.tb_lineno,
                     'file': fname})


class Null(object):
    def __init__(self, *args, **kwargs):
        return None

    def __call__(self, *args, **kwargs):
        return self

    def __getattr__(self, mname):
        return self

    def __setattr__(self, name, value):
        return self

    def __delattr__(self, name):
        return self

    def __repr__(self):
        return "<Null>"

    def __str__(self):
        return "Null"


class DefaultClassMethods(type):
    def __getattr__(cls, attr):
        if str(attr).upper() not in OPS:
            raise AttributeError(attr)
        if 'ADD' == str(attr).upper():
            @rollback
            def _defaultClassMethod(cls, client, data):
                return cls.element(client, attr, data)
        else:
            def _defaultClassMethod(cls, client, data):
                return cls.element(client, attr, data)
        return MethodType(_defaultClassMethod, cls, cls.__metaclass__)

def rollback(func):
    def wrapper(cls, *args):
        result = func(cls, *args)
        rollback = {} if not result else \
            cls._prepare_rollback(cls.delete, *args, **result)
        return {'result': result, 'rollback': rollback}
    return wrapper

class Base(object):
    __metaclass__ = DefaultClassMethods

    def __init__(self):
        self.exist = False
        self.rollback = None

    @staticmethod
    def params_decoded(*args):
        keys = ['client', 'data']
        return dict(zip(keys, args))

    @classmethod
    def _prepare_rollback(cls, func, *args, **result):
        if not func:
            return None
        params = cls.params_decoded(*args)
        data = cls._rollback_data(params, **result)
        rollback = {
            'func': func,
            'params': (params['client'], data)
        }
        return rollback

    @classmethod
    def _rollback_data(cls, params, **result):
        return {
            'vdom': params['data'].get('vdom', const.EXT_VDOM),
            'name': params['data']['name']
        }

    @classmethod
    def element(cls, client, action, data):
        funcinfo()
        if not data:
            data = getattr(cls, 'data', None)
        # op is the combination of action and resource class name,
        # all ops should be defined in the templates
        name = re.findall("[A-Z][^A-Z]*", cls.__name__)
        op = "%s_%s" % (str(action).upper(), "_".join(name).upper())
        try:
            return client.request(op, **data)
        except api_ex.ApiException as e:
            Exinfo(e)
            raise e


#############################################################


#############################################################

class Vdom(Base):
    def __init__(self):
        super(Vdom, self).__init__()

    @classmethod
    def _rollback_data(cls, params, **result):
        return {'name': params['data'].get('name')}

class VdomLink(Base):
    def __init__(self):
        super(VdomLink, self).__init__()

class VlanInterface(Base):
    def __init__(self):
        super(VlanInterface, self).__init__()

"""
    @classmethod
    def get_with_params_check(cls, driver, data):
        res = cls.get(driver, data)
        for key, value in data.iteritems():
            if value != res['results'][0].get(key):
                res = cls.set(driver, data)
                break
        return res
"""

class RouterStatic(Base):
    def __init__(self):
        super(RouterStatic, self).__init__()

    @classmethod
    def _rollback_data(cls, params, **result):
        return {
            'vdom': params['data']['vdom'],
            'id': result['results']['mkey']
        }

class FirewallIppool(Base):
    def __init__(self):
        super(FirewallIppool, self).__init__()

class FirewallPolicy(Base):
    def __init__(self):
        super(FirewallPolicy, self).__init__()

    @classmethod
    def _rollback_data(cls, params, **result):
        return {
            'vdom': params['data']['vdom'],
            'id': result['results']['mkey']
        }

class FirewallAddress(Base):
    def __init__(self):
        super(FirewallAddress, self).__init__()


class FirewallAddrgrp(Base):
    def __init__(self):
        super(FirewallAddrgrp, self).__init__()


class DhcpServer(Base):
    def __init__(self):
        super(DhcpServer, self).__init__()

    @classmethod
    def _rollback_data(cls, params, **result):
        return {
            'vdom': params['data']['vdom'],
            'id': result['results']['mkey']
        }

class DhcpServerRsvAddr(Base):
    def __init__(self):
        super(DhcpServerRsvAddr, self).__init__()


class FirewallVip(Base):
    def __init__(self):
        super(FirewallVip, self).__init__()


if __name__ == "__main__":
    from neutron.plugins.ml2.drivers.fortinet.api_client.client \
        import FortiosApiClient

    api = [("10.160.37.96", 80, False)]
    user = "admin"
    password = ""
    cli = FortiosApiClient(api, user, password)
    #r = RouterStatic()

    data = {'name': 'port9', 'vdom': 'root'}
    data_test = {"name": "vdm_test"}
    data1 = {
        "vdom": "osvdmext",
        "dst": "0.0.0.0 0.0.0.0",
        "device": "port9",
        "gateway": "10.16.37.1"
    }
    print VlanInterface.get(cli, data)