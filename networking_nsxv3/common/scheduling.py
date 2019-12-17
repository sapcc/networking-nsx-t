import os
import time
import functools
import collections

from oslo_log import log as logging

if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()

LOG = logging.getLogger(__name__)


class Scheduler(object):

    def __init__(self, rate=1, limit=1.0, callback=None):

        if limit <= 0:
            raise ValueError('Schedule limit "{}" not positive'.format(limit))
        if rate <= 0:
            raise ValueError('Schedule rate "{}" not positive'.format(rate))

        self.schedule = collections.deque()

        self.rate = rate
        self.limit = limit
        self.callback = callback
        self._semaphore = eventlet.semaphore.Semaphore(value=self.rate)

    def __call__(self, func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            with self:
                return func(*args, **kwargs)
        return wrapped

    def __enter__(self):
        self._semaphore.acquire(blocking=True, timeout=3)
        run_time = time.time()
        offset = len(self.schedule) - self.rate

        if offset >= 0 and run_time - self.limit < self.schedule[offset]:
            sleeptime = run_time - self.schedule[offset] + self.limit
            if self.callback:
                eventlet.spawn(self.callback, sleeptime)
            run_time = self.schedule[offset] + self.limit
            eventlet.greenthread.sleep(sleeptime)
        self.schedule.append(run_time)
        LOG.debug("Executing function at {}".format(time.time()))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._semaphore.release()
        now = time.time()
        while self.schedule and self.schedule[0] < now - self.limit:
            self.schedule.popleft()
