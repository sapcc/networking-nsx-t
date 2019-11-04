import os
from enum import Enum
from oslo_log import log as logging
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class Priority(Enum):
    HIGHEST = 0
    HIGHER = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    LOWER = 5
    LOWEST = 6


class Synchronizer(object):

    def __init__(self, scheduler, queue_size=-1, workers_count=1):
        # if queue_size is < 0, the queue size is infinite.
        self._queue = eventlet.queue.PriorityQueue(maxsize=queue_size)
        self._workers = eventlet.greenpool.GreenPool(size=workers_count)
        self._scheduler = scheduler
        self._tasks = dict()
        self._tasks_semaphor = eventlet.semaphore.Semaphore()

    def submit_task(self, priority, os_ids, sync_fn):
        if priority != Priority.HIGHEST:
            with self._tasks_semaphor:
                self._tasks[priority] = os_ids
        for os_id in os_ids:
            try:
                LOG.debug("Synchronization enqueued for '{}'".format(os_id))
                item = (priority.value, {"id": os_id, "fn": sync_fn})
                self._queue.put_nowait(item)
            except eventlet.queue.Full as err:
                LOG.error(
                    "Synchronization queue is full. Unable to handle '{}'"
                    .format(os_id), err)

    def start(self):
        eventlet.greenthread.spawn_n(self._start)

    def stop(self):
        self._workers.waitall()

    def has_task_completed(self, priority):
        if priority in self._tasks:
            return len(self._tasks[priority]) == 0
        return True

    def _start(self):
        while True:
            priority_value, job = self._queue.get(block=True)
            priority = Priority(priority_value)
            LOG.debug("Synchronizing object '{}'".format(job["id"]))
            with self._scheduler:
                gt = self._workers.spawn(job["fn"], job["id"])
                if priority != 0:
                    gt.link(self._update_task, [priority, job["id"]])

    def _update_task(self, _, args):
        priority = args[0]
        os_id = args[1]
        with self._tasks_semaphor:
            if priority in self._tasks and os_id in self._tasks[priority]:
                self._tasks[priority].remove(os_id)
