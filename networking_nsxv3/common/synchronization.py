"""
Synchronization - classes related concurrent execution scheduling and limits
"""
import eventlet
eventlet.monkey_patch()

import networking_nsxv3.prometheus.exporter as EXPORTER
from oslo_log import log as logging
from oslo_config import cfg
import enum
import time
import json
import heapq
import functools
import collections


LOG = logging.getLogger(__name__)

MESSAGE = "{} Resource ID: {} with Priority: {} for action {}"
INFINITY = -1
TIMEOUT = 5


class Priority(enum.IntEnum):
    """ The acceptable by the Runner.class priorities """
    HIGHEST = 0
    HIGHER = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    LOWER = 5
    LOWEST = 6


class Identifier(object):

    def __init__(self, identifier):
        self.identifier = identifier
        self.retry = 0
        self._retry_max = cfg.CONF.AGENT.retry_on_failure_max
        self._retry_delay = cfg.CONF.AGENT.retry_on_failure_delay

    def encode(self):
        return json.dumps({
            "id": self.identifier,
            "retry": self.retry
        })

    @staticmethod
    def decode(identifier):
        try:
            options = json.loads(identifier)
        except ValueError as e:
            return Identifier(identifier)
        obj = Identifier(options["id"])
        obj.retry = options["retry"]
        return obj

    def retry_next(self):
        if self.retry <= self._retry_max:
            self.retry += 1
            eventlet.sleep(self._retry_delay)
            return True
        return False


class Runnable(object):

    def __init__(self, idn, fn, priority=Priority.LOWEST):
        self.priority = priority
        self.idn = idn
        self.fn = fn

    def __repr__(self):
        return str(self.idn)

    def __eq__(self, other):
        """
        Note, the priority is not part of the comparison
        Thus if a runnable with higher priority is about to be
        added to the queue it will be rejected silently.
        """
        if isinstance(other, Runnable):
            return (self.idn == other.idn and self.fn == other.fn)
        else:
            return False

    def __ne__(self, other):
        return (not self.__eq__(other))

    def __lt__(self, other):
        """ Order Runnable by their priority """
        return self.priority < other.priority

    def __hash__(self):
        return hash(self.__repr__())


class UniqPriorityQueue(eventlet.queue.Queue):

    def _init(self, maxsize):
        self.queue = []

    def _put(self, item, heappush=heapq.heappush):
        if item not in self.queue:
            heappush(self.queue, item)
        self._put_bookkeeping()

    def _get(self, heappop=heapq.heappop):
        return heappop(self.queue)


class Runner(object):
    """ Synchronization.Runner.class runs jobs with priorities.
    It uses two types of queue:
    Active - containing all jobs that are ready to be executed.
             Workers pick immediately work from this queue.
    Passive - containing all jobs submitted with lower than Priority.HIGHEST.
              A job is transferred from passive to active queue only when the
              active queue size is less than 'workers_size'.

    Keyword arguments:
    active_size -- the size of the active queue
    passive_size -- the size of the passive queue
    workers_size -- number of worker's processing jobs from the active queue
    """

    def __init__(self, active_size=INFINITY, passive_size=INFINITY,
                 workers_size=1):
        # if queue_size is < 0, the queue size is infinite.
        self._active = UniqPriorityQueue(maxsize=active_size)
        self._passive = UniqPriorityQueue(maxsize=passive_size)
        self._workers = eventlet.greenpool.GreenPool(size=workers_size)
        self._idle = workers_size
        self._state = "not started"

    def run(self, priority, ids, fn):
        """ Submit a job with priority

        Keyword arguments:
        priority -- job priority of type Priority.class
        ids -- list of IDs (identifiers) that will be passed to the 'fn'
        fn -- a function about to be executed by the runner with an argument ID
        """
        if self._state != "started":
            report = MESSAGE.format("Skipping", ids, priority.name, fn.__name__)
            LOG.warn("Runner is in State:%s .%s", self._state, report)
            return

        for jid in ids:
            try:
                LOG.info(MESSAGE.format("Enqueued", jid, priority.name, fn.__name__))

                job = Runnable(jid, fn, priority.value)
                if priority.value == Priority.HIGHEST:
                    self._active.put_nowait(job)
                else:
                    self._passive.put_nowait(job)
            except eventlet.queue.Full as err:
                LOG.error(MESSAGE.format(err, jid, priority.name, fn.__name__))

    def _start(self):
        while True:
            try:
                if self._workers.size == 0:
                    LOG.info("Terminating... Workers pool reached size of 0.")
                    return
                if self.active() < self._idle and self.passive() > 0:
                    self._active.put_nowait(self._passive.get_nowait())
                    self._passive.task_done()
                job = self._active.get(block=True, timeout=TIMEOUT)
                LOG.info(MESSAGE.format("Processing", job.idn, Priority(job.priority).name, job.fn.__name__))
                self._workers.spawn(job.fn, job.idn)#.wait()
                self._active.task_done()
            except eventlet.queue.Empty:
                LOG.info("No activity for the last {} seconds.".format(TIMEOUT))
                LOG.info("Sizes Queue[Active=%s, Passive=%s], Jobs=%s",
                    self.active(), self.passive(), self._workers.running())
            except Exception as err:
                # Continue on error. Otherwise the agent operation will stop
                LOG.error(err)
            EXPORTER.ACTIVE_QUEUE_SIZE.set(self.active())
            EXPORTER.PASSIVE_QUEUE_SIZE.set(self.passive())
            EXPORTER.JOB_SIZE.set(self._workers.running())

    def active(self):
        """ Returns that size of the active queue """
        return self._active.qsize()

    def passive(self):
        """ Returns that size of the passive queue """
        return self._passive.qsize()

    def start(self):
        """ Initialize the runner instance """
        self._state = "started"
        eventlet.greenthread.spawn(self._start)
        eventlet.sleep(0)

    def stop(self):
        """ Gracefully terminates the runner instance """
        self._state = "stopping"
        while True:
            a = self.active()
            p = self.passive()
            w = self._workers.running()
            LOG.info("Terminating... Waiting for all active work to complete")
            LOG.info("Sizes Queue[Active=%s, Passive=%s], Jobs=%s", a, p, w)
            if a == 0 and p == 0:
                break
            eventlet.sleep(5)

        self._workers.resize(0)
        self._workers.waitall()
        self._state = "stopped"
        LOG.info("Job Queue workers terminated successfully.")

    def wait_active_jobs_completion(self):
        self._active.join()

    def wait_passive_jobs_completion(self):
        self._passive.join()

    def wait_all_workers(self):
        eventlet.sleep(0)
        self._workers.waitall()


class Scheduler(object):
    """ Synchronization.Scheduler.class limits the rate of execution of
        'with' section

        Keyword arguments:
        rate -- the rate of execution
        limit -- the limit of execution
    """

    def __init__(self, rate=1, limit: int = 1, timeout=5):

        if limit <= 0:
            raise ValueError('Schedule limit "{}" not positive'.format(limit))
        if rate <= 0:
            raise ValueError('Schedule rate "{}" not positive'.format(rate))

        self.schedule = collections.deque()

        self.rate = rate
        self.limit = limit
        self.timeout = timeout

        # Callback reporting the limit was hit
        def callback(seconds):
            LOG.warning('NSXv3 API Limit {:d}/s was hit. Sleeping for {:f}s.'.format(limit, seconds))

        self.callback = callback
        self._semaphore = eventlet.semaphore.Semaphore(value=self.rate)

    def __call__(self, func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            with self:
                return func(*args, **kwargs)
        return wrapped

    def __enter__(self):
        if self._semaphore.acquire(blocking=True, timeout=self.timeout):
            run_time = time.time()
            offset = len(self.schedule) - 1 - self.rate

            if offset >= 0 and run_time - self.limit < self.schedule[offset]:
                sleeptime = run_time - self.schedule[offset] + self.limit
                if self.callback:
                    eventlet.spawn(self.callback, sleeptime)
                eventlet.greenthread.sleep(sleeptime)
                run_time = self.schedule[offset] + self.limit
            self.schedule.append(run_time)
            return self
        raise Exception("{} Queue Size={}, Rate={}, Limit={}, Timeout={}"
            .format("Timeout reached of trying to schedule operation.",
                    len(self.schedule), self.rate, self.limit, self.timeout))

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._semaphore.release()
        now = time.time()
        while self.schedule and self.schedule[0] < now - self.limit:
            self.schedule.popleft()
