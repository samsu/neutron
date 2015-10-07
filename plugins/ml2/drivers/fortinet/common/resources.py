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


from neutron.plugins.ml2.drivers.fortinet.api_client \
    import exception as api_ex


OPS = ["ADD", "DELETE", "SET", "GET", "MOVE"]
RB_FUNC = {'add': 'delete'}

class Exinfo(object):
    def __init__(self, exception):
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "#############"
        print(exc_type, fname, exc_tb.tb_lineno)
        template = "An exception of type {0} occured. Arguments:\n{1!r}"
        message = template.format(type(exception).__name__, exception.args)
        print message
        print "#############"

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
        self.name = re.findall("[A-Z][^A-Z]*", self.__class__.__name__)
        self.name = "_".join(self.name).upper()
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
        @functools.wraps(func)
        def wrapper(self, *args):
            print "func=%s" % func.__name__
            result = func(self, *args)
            rollback = {} if not result else \
                self._prepare_rollback(self.delete, *args, **result)
            return {'result': result, 'rollback': rollback}
        return wrapper
    rollback = staticmethod(rollback)

    def element(self, client, action, data=None):
        if not data:
            data = self.data
        # op is the combination of action and resource class name,
        # all ops should be defined in the templates
        op = "%s_%s" % (str(action).upper(), self.name)
        try:
            return client.request(op, **data)
        except api_ex.ApiException as e:
            Exinfo(e)
            raise e

    def __getattr__(self, action):
        if str(action).upper() not in OPS:
            raise AttributeError(action)
        def wrapper(client, data):
            return self.element(client, action, data)
        return wrapper


    def is_exist(self, client, **kwargs):
        response = client.request(self.method("get"), kwargs)
        if httplib.OK == response["http_status"]:
            return True
        return False

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


class Test(object):
    vdom_name = "Test class"

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
    data1 = {
        "vdom": "root",
        "dst": "10.16.37.0 255.255.255.0",
        "device": "port31",
        "gateway": "10.16.37.1"
    }
    #a.get(cli)
    #print r.get(cli, data)
    print r.add(cli, data1)


"""
    print "FirewallPolicy.vdom_name=%s" % FirewallPolicy.vdom_name
    print "a.message=%s" % a.message
    print "a.a=%s" % a.a
    a.vdom_name = "test121"
    FirewallPolicy.vdom_name="abc"
    print "FirewallPolicy.vdom_name=%s" % FirewallPolicy.vdom_name
    print "a.message=%s" % a.message
    print "a.vdom_name=%s" % a.vdom_name
    print "a.a=%s" % a.a
"""
