# Copyright 2015 Fortinet, Inc.
# All Rights Reserved
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

import collections
import uuid

from eventlet import event
from eventlet import greenthread

from neutron.common import exceptions
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.ml2.drivers.fortinet.tasks import constants
from neutron.plugins.ml2.drivers.fortinet.tasks import singleton
from neutron.plugins.ml2.drivers.fortinet.common import resources

##### test purpose
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
#####

DEFAULT_INTERVAL = 1000
DEBUG = False

LOG = logging.getLogger(__name__)

def nop(task):
    return constants.TaskStatus.COMPLETED


class TaskException(exceptions.NeutronException):

    def __init__(self, message=None, **kwargs):
        if message is not None:
            self.message = message
        super(TaskException, self).__init__(**kwargs)


class InvalidState(TaskException):
    message = _("Invalid state %(state)d")


class TaskStateSkipped(TaskException):
    message = _("State %(state)d skipped. Current state %(current)d")


class Tasks(object):
    def __init__(self, id):
        #self.name = name if name else uuid.uuid1()
        #self.client = client
        # self._tasks is a stack to store the rollback tasks of tasks executed.
        # self._tasks example
        # [
        #   {
        #       'data': {'vdom': 'osvdm1'},
        #       'func': <function wrapper at 0x3ee2140>
        #   },
        #   {
        #       'data': {'vdom': 'osvdm1'},
        #       'func': <function wrapper at 0x3ee21b8>
        #   }
        # ]
        self._tasks = collections.deque()
        # task id should be unified, here we can use context.request_id
        self.id = id if id else str(uuid.uuid1())
        self.state = event.Event()
        self.status = constants.TaskStatus.NONE
        self.status_handlers = {
            constants.TaskStatus.ROLLBACK: self.execute,
            constants.TaskStatus.COMPLETED: self._finished,
            constants.TaskStatus.ERROR: self._finished,
            constants.TaskStatus.ABORT: self._finished
        }

    def register(self, **subtask):
        if DEBUG:
            import ipdb; ipdb.set_trace()
        if subtask in self._tasks:
            return
        self._tasks.append(subtask)
        self._update_status(constants.TaskStatus.PENDING)
        return self

    def _reset_tasks(self, status=constants.TaskStatus.NONE):
        while len(self._tasks):
            self._tasks.pop()
        self.status = status

    def execute(self):
        if constants.TaskStatus.ROLLBACK != self.status:
            print "### the current status is %s" % self.status
            return
        while len(self._tasks):
            try:
                subtask = self._tasks.pop()
                import ipdb;ipdb.set_trace()
                subtask['func'](*subtask['params'])
                #print "### response = %s" % response
            except Exception as e:
                msg = _("Task %(task)s encountered exception in %(func)s ") % \
                        { 'task': str(self), 'func': str(subtask['func'])}
                self.status = constants.TaskStatus.ERROR
                self._tasks = {}
                #print "### failed self._task = %s" % self._tasks
                LOG.exception(msg)
        return self._update_status(constants.TaskStatus.COMPLETED)

    def _update_status(self, status):
        if status != self.status:
            self.status = status
            if status in self.status_handlers.keys():
                self.status_handlers[status]()
        return self.status

    def _finished(self):
        self._reset_tasks(constants.TaskStatus.COMPLETED)

    def wait(self):
        print "#### task wait()"
        if constants.TaskStatus.NONE == self.status:
            return
        print "#### task wait() = %s" % self.status
        status = self.state.wait()
        print "### status =%s" % status
        if DEBUG:
            import ipdb; ipdb.set_trace()
        self.status_handlers[status]()

    def __repr__(self):
        return "Task-%s" % (self.id)

@singleton.singleton
class TaskManager(object):

    _instance = None
    _default_interval = DEFAULT_INTERVAL

    def __init__(self, interval=None):
        self._interval = interval or TaskManager._default_interval

        # A queue to pass tasks from other threads
        self._tasks_queue = collections.deque()

        # A dict to task id
        self._tasks = {}

        # Current task being executed in main thread
        self._main_thread_exec_task = None

        # New request event
        self._req = event.Event()

        # TaskHandler stopped event
        self._stopped = False

        # Periodic function trigger
        self._monitor = None
        self._monitor_busy = False

        # Thread handling the task request
        self._thread = None

    def _execute(self, task):
        """Execute task."""
        msg = _("@@@ Start task %s") % str(task)
        LOG.debug(msg)
        #task._start()
        try:
            task.wait()
        except Exception:
            msg = _("Task %(task)s encountered exception") % \
                {'task': str(task)}
            LOG.exception(msg)
            status = constants.TaskStatus.ERROR
        LOG.debug("Task %(task)s return", {'task': str(task)})


    def _result(self, task):
        """Notify task execution result."""
        try:
            return
        except Exception:
            msg = _("Task %(task)s encountered exception in %(cb)s") % {
                'task': str(task),
                'cb': str(task._result_callback)}
            LOG.exception(msg)

        LOG.debug("Task %(task)s return %(status)s",
                  {'task': str(task), 'status': task.status})

        task._finished()

    def _check_pending_tasks(self):
        """Check all pending tasks status."""
        print "self._tasks=%s" % self._tasks
        print "# self._tasks.keys=%s" % self._tasks.keys()
        print "# self._stopped=%s" % self._stopped

        for id in self._tasks.keys():
            if self._stopped:
                # Task manager is stopped, return now
                return

            task = self._tasks[id]
            print "# tasks=%s" % task
            # only the first task is executed and pending
            if DEBUG:
                import ipdb;ipdb.set_trace()
            if constants.TaskStatus.PENDING != task.status:
                self._dequeue(task)

    def _enqueue(self, id):
        if id not in self._tasks:
            self._tasks[id] = Tasks(id)
            self._tasks_queue.append(self._tasks[id])

    def _dequeue(self, task):
        #self._result(task)
        if task in self._tasks_queue:
            self._tasks_queue.remove(task)
            del self._tasks[task.id]
            return

    def update_status(self, id, status):
        if DEBUG:
            import ipdb; ipdb.set_trace()
        if id in self._tasks:
            self._tasks[id]._update_status(status)

    def _abort(self):
        """Abort all tasks."""
        # put all tasks haven't been received by main thread to queue
        # so the following abort handling can cover them
        for t in self._tasks_queue:
            self._enqueue(t)
        self._tasks_queue.clear()

        for id in self._tasks.keys():
            tasks = list(self._tasks[id])
            for task in tasks:
                task._update_status(constants.TaskStatus.ABORT)
                self._dequeue(task)

    def _get_task(self):
        """Get task request."""
        while True:
            print "# self._req = %s" % self._req
            for t in self._tasks_queue:
                if t.status in [constants.TaskStatus.ROLLBACK,
                                constants.TaskStatus.COMPLETED]:
                #return self._tasks_queue.popleft()
                    return t
            self._req.wait()
            self._req.reset()

    def run(self):
        while True:
            try:
                if self._stopped:
                    # Gracefully terminate this thread if the _stopped
                    # attribute was set to true
                    LOG.info(_("Stopping TaskManager"))
                    break

                # get a task from queue, or timeout for periodic status check

                task = self._get_task()
                print "# task=%s, task.id=%s" % (task, task.id)
                """
                if task.id in self._tasks:
                    # this resource already has some tasks under processing,
                    # append the task to same queue for ordered processing
                    self._enqueue(task)
                    continue
                """
                try:
                    #if constants.TaskStatus.ROLLBACK == task.status:
                    self._main_thread_exec_task = task
                    self._execute(task)
                finally:
                    self._main_thread_exec_task = None
                    print "##@### task=%s, task.status=%s" % (task, task.status)
                    if task.status in [constants.TaskStatus.NONE,
                                       constants.TaskStatus.ERROR,
                                       constants.TaskStatus.COMPLETED]:
                        # The thread is killed during _execute(). To guarantee
                        # the task been aborted correctly, put it to the queue.
                        #self._enqueue(task)
                        self._dequeue(task)
                    else:
                        self._enqueue(task)
            except Exception:
                LOG.exception(_("TaskManager terminating because "
                                "of an exception"))
                break

    def add(self, id, **subtask):
        if id is None:
            id = str(uuid.uuid1())
            print "No id input, generate a id %(id)s instead" % {'id': id}
        if subtask:
            self._enqueue(id)
            self._tasks[id].register(**subtask)


    def stop(self):
        if self._thread is None:
            return
        self._stopped = True
        self._thread.kill()
        self._thread = None
        # Stop looping call and abort running tasks
        self._monitor.stop()
        if self._monitor_busy:
            self._monitor.wait()
        self._abort()
        LOG.info(_("TaskManager terminated"))

    def has_pending_task(self):
        if self._tasks_queue or self._tasks or self._main_thread_exec_task:
            return True
        else:
            return False

    def show_pending_tasks(self):
        for task in self._tasks_queue:
            LOG.info(str(task))
        for resource, tasks in self._tasks.iteritems():
            for task in tasks:
                LOG.info(str(task))
        if self._main_thread_exec_task:
            LOG.info(str(self._main_thread_exec_task))

    def count(self):
        count = 0
        for id, tasks in self._tasks.iteritems():
            count += len(tasks)
        return count

    def start(self, interval=None):
        def _inner():
            self.run()

        def _loopingcall_callback():
            self._monitor_busy = True
            try:
                self._check_pending_tasks()
            except Exception as e:
                resources.Exinfo(e)
                LOG.exception(_("Exception in _check_pending_tasks"))
            self._monitor_busy = False

        if self._thread is not None:
            return self

        if interval is None or interval == 0:
            interval = self._interval

        self._stopped = False
        self._thread = greenthread.spawn(_inner)
        self._monitor = loopingcall.FixedIntervalLoopingCall(
            _loopingcall_callback)
        print "###### self._monitor=%s" % self._monitor
        self._monitor.start(interval / 1000.0,
                            interval / 1000.0)
        # To allow the created thread start running
        greenthread.sleep(0)

        return self

    @classmethod
    def set_default_interval(cls, interval):
        cls._default_interval = interval


class Context(object):
    def __init__(self, connection=None):
        if not connection:
            connection = "mysql://neutron:neutron@10.160.37.101:3306/neutron"
        engine = create_engine(connection)
        DBSession = sessionmaker(bind=engine)
        self.session = DBSession()


if __name__ == "__main__":
    import time
    from neutron.plugins.ml2.drivers.fortinet.api_client.client \
        import FortiosApiClient
    from neutron.plugins.ml2.drivers.fortinet.common.resources import *
    from neutron.plugins.ml2.drivers.fortinet.db import models as fortinet_db
    context = Context()
    DEBUG = False
    try:
        tm = TaskManager()
        tm.start()
        if DEBUG:
            import ipdb; ipdb.set_trace()

        id = "abc-adbc"

        api = [("10.160.37.95", 80, False)]
        user = "admin"
        password = ""
        cli = FortiosApiClient(api, user, password)

        a = FirewallPolicy()
        r = RouterStatic()
        data0 = {"vdom": "root", "id": 2}
        #data = {"vdom": "root"}
        record = {
            'subnet_id': 'aadfadfadfadfsdfas',
            'vdom': 'root',
            'edit_id': 2
        }
        data1 = {
            "vdom": "root",
            "dst": "10.16.37.0 255.255.255.0",
            "device": "port31",
            "gateway": "10.16.37.1"
        }
        data2 = {
            "vdom": "root",
            "dst": "10.17.37.0 255.255.255.0",
            "device": "port21",
            "gateway": "10.17.37.1"
        }

        #"""
        dbr = fortinet_db.Fortinet_Static_Router()
        db_rollback = {
            'params': (context, record),
            'func': dbr.delete
        }

        t = Tasks(id)

        tm.add(id, **db_rollback)
        params1 = (context, record)

        res = dbr.add(*params1)
        print "# Fortinet_Static_Router = %s\n" % res
        context.session.commit()
        params = (cli, data0)
        import ipdb; ipdb.set_trace()
        tm.update_status(id, constants.TaskStatus.ROLLBACK)
        context.session.commit()
        """
        try:
            import ipdb; ipdb.set_trace()
            resdb = dbr.add(*params1)
            print "# Fortinet_Static_Router.query = %s\n" % resdb
            #tm.add(id, )
            context.session.commit()
        except Exception as e:
            resources.Exinfo(e)
            import ipdb; ipdb.set_trace()
            tm.update_status(id, constants.TaskStatus.ROLLBACK)
        """
        #t.add_start_monitor(func=dbr.add, params=params1)
        #t.add_start_monitor(func=dbr.query, params=params1)
        #t.add_start_monitor(func=dbr.delete, params=params1)

        #t.register(func=r.get, params=params)

        ################

        """
        res = {
            'rollback':
                {'params': (
                    <neutron.plugins.ml2.drivers.fortinet.api_client.client.FortiosApiClient object at 0x2a14a90>,
                    {'id': 2, 'vdom': 'root'}
                ),
                'func': <function wrapper at 0x2b62ed8>
                },
            'result': {
                u'status': u'success',
                u'name': u'static',
                u'version': u'v5.2.3',
                u'results': {
                    u'mkey': 2
                },
                u'http_method': u'POST',
                u'build': 670,
                u'http_status': 200,
                u'path': u'router',
                u'serial': u'FG1K5D3I13800125',
                u'vdom': u'root'
            }
        }
        """
        """
        res = r.add(cli, data1)
        print "################"
        print "##### res = %s" % res
        print "################"
        if DEBUG:
            import ipdb; ipdb.set_trace()
        tm.add(id, **res['rollback'])
        res = r.add(cli, data2)
        tm.add(id, **res['rollback'])
        RB = 1
        FN = 0
        if RB:
            try:
                time.sleep(1)
                res = r.add(cli, data2)
                print "res = %s" % res
                tm.add(id, **res['rollback'])
            except Exception:
                tm.update_status(id, constants.TaskStatus.ROLLBACK)
        #tm._tasks[id].status = constants.TaskStatus.ROLLBACK
        if FN:
            tm.update_status(id, constants.TaskStatus.COMPLETED)
        time.sleep(5)
        #t.add_start_monitor(func=r.add, params=params)
        if DEBUG:
            import ipdb; ipdb.set_trace()
        #r.get(cli, data)

        #context.session.commit()
        print "##################################"
        #a.get(cli, data)
        """
        ################

    except Exception as e:
        resources.Exinfo(e)

