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

from oslo.config import cfg
from neutron.agent.common import config
import re
import httplib
import sys
import os
import functools

from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.fortinet.api_client \
    import exception as api_ex

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

class Base(object):
    def __init__(self):
        self.exist = False
        self.rollback = None

    @staticmethod
    def func_name():
        return sys._getframe(1).f_code.co_name

    def update_db(self, context, table):
        try:
            for key, value in kwargs.iteritems():
                setattr(record, key, value)
            session = context.session
            with session.begin(subtransactions=True):
                session.add(record)
        except:
            raise Exception

    @staticmethod
    def params_decoded(*args):
        keys = ['client', 'data']
        return dict(zip(keys, args))

    def rollback(func):
        #@functools.wraps(func)
        def wrapper(cls, *args):
            print "func=%s" % func.__name__
            result = func(cls, *args)
            rollback = {} if not result else \
                cls._prepare_rollback(cls.delete, *args, **result)
            return {'result': result, 'rollback': rollback}
        return wrapper
    rollback = staticmethod(rollback)

    @classmethod
    def element(cls, client, action, data=None):
        if not data:
            data = getattr(cls, 'data', None)
        # op is the combination of action and resource class name,
        # all ops should be defined in the templates
        name = re.findall("[A-Z][^A-Z]*", cls.__class__.__name__)
        #tpl_name = "_".join(name).upper()
        op = "%s_%s" % (str(action).upper(), "_".join(name).upper())
        try:
            return client.request(op, **data)
        except api_ex.ApiException as e:
            Exinfo(e)
            raise e

    @classmethod
    def __getattr__(cls, action):
        if str(action).upper() not in OPS:
            raise AttributeError(action)
        def wrapper(client, data):
            return cls.element(client, action, data)
        return wrapper

    def is_exist(self, client, **kwargs):
        response = client.request(self.method("get"), kwargs)
        if httplib.OK == response["http_status"]:
            return True
        return False

#############################################################


#############################################################

class Vdom(Base):
    def __init__(self):
        super(Vdom, self).__init__()

    @Base.rollback
    @classmethod
    def add(cls, *args):
        """
        args is a tuple, its format is (api_client, {"key": value, })
        """
        return super(Vdom, cls).__getattr__('add')(*args)
        #print "add() response = %s" % response

    @classmethod
    def _prepare_rollback(cls, func, *args, **result):
        if not func:
            return None
        params = cls.params_decoded(*args)
        data = {'name': params['data'].get('name')}
        rollback = {
            'func': func,
            'params': (params['client'], data)
        }
        return rollback


class VlanInterface(Base):
    def __init__(self):
        super(VlanInterface, self).__init__()

    @Base.rollback
    def add(cls, *args):
        """
        args is a tuple, its format is (api_client, {"key": value, })
        """
        return super(VlanInterface, cls).__getattr__('add')(*args)
        #print "add() response = %s" % response

    @classmethod
    def _prepare_rollback(cls, func, *args, **result):
        if not func:
            return None
        params = cls.params_decoded(*args)
        data = {
            'vdom': params['data'].get('vdom'),
            'name': params['data'].get('name')
        }
        rollback = {
            'func': func,
            'params': (params['client'], data)
        }
        return rollback


class RouterStatic(Base):
    def __init__(self):
        super(RouterStatic, self).__init__()

    @Base.rollback
    def add(self, *args):
        """
        args is a tuple, its format is (api_client, {"key": value, })
        """
        return super(RouterStatic, self).__getattr__('add')(*args)
        #print "add() response = %s" % response


    def _prepare_rollback(self, func, *args, **result):
        if not func:
            return None
        params = self.params_decoded(*args)
        data = {
            'vdom': params['data']['vdom'],
            'id': result['results']['mkey']
        }
        rollback = {
            'func': func,
            'params': (params['client'], data)
        }
        return rollback


class FirewallPolicy(Base):
    def __init__(self):
        super(FirewallPolicy, self).__init__()
        self.data = {
            "vdom": "root",
            "srcintf": "any",
            "dstintf": "any",
            "srcaddr": "all",
            "dstaddr": "all"
        }




if __name__ == "__main__":
    from neutron.plugins.ml2.drivers.fortinet.api_client.client \
        import FortiosApiClient

    api = [("10.160.37.95", 80, False)]
    user = "admin"
    password = ""
    cli = FortiosApiClient(api, user, password)
    a = FirewallPolicy()
    r = RouterStatic()

    data = {"vdom": "osvdm1"}
    data_test = {"name": "os_tst1"}
    data1 = {
        "vdom": "root",
        "dst": "10.16.37.0 255.255.255.0",
        "device": "port31",
        "gateway": "10.16.37.1"
    }
    import ipdb;ipdb.set_trace()
    Vdom.__getattr__('get')(cli, data_test)
    print Vdom.get(cli, data_test)
    #a.get(cli)
    #print r.get(cli, data)
    print r.add(cli, data1)


"""
    print "FirewallPolicy.vdom=%s" % FirewallPolicy.vdom
    print "a.message=%s" % a.message
    print "a.a=%s" % a.a
    a.vdom = "test121"
    FirewallPolicy.vdom="abc"
    print "FirewallPolicy.vdom=%s" % FirewallPolicy.vdom
    print "a.message=%s" % a.message
    print "a.vdom=%s" % a.vdom
    print "a.a=%s" % a.a
"""
