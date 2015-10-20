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
from neutron.plugins.ml2.drivers.fortinet.common import resources as resources
from neutron.plugins.ml2.drivers.fortinet.tasks import constants as t_consts

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

def _rollback_on_err(obj, context, err):
    obj.task_manager.update_status(getid(context),
                                   t_consts.TaskStatus.ROLLBACK)
    resources.Exinfo(err)
