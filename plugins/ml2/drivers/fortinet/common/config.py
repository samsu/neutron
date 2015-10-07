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

ML2_FORTINET = [cfg.StrOpt('address', default='',
                          help=_('The address of fortigates to connect to')),
               cfg.StrOpt('username', default='admin',
                          help=_('The username used to login')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=_('The password used to login')),
               cfg.StrOpt('int_interface', default='internal',
                          help=_('The interface to serve tenant network')),
               cfg.StrOpt('ext_interface', default='',
                          help=_('The interface to the external network')),
               cfg.StrOpt('tenant_network_type', default='vlan',
                          help=_('tenant network type, default is vlan')),
               cfg.StrOpt('vlink_vlan_id_range', default='3900:4000',
                          help=_('vdom link vlan interface, default is 3000:4000')),
               cfg.StrOpt('vlink_ip_range', default='169.254.0.0/26',
                          help=_('vdom link interface IP range, '
                                 'default is 169.254.0.0/20')),
               cfg.StrOpt('vip_mappedip_range', default='169.254.128.0/26',
                          help=_('vdom link interface IP range, '
                                 'default is 169.254.128.0/20'))
               ]

cfg.CONF.register_opts(ML2_FORTINET, "ml2_fortinet")
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)
