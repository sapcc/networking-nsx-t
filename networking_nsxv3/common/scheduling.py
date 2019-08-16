import os
import time
import functools
import collections

if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()


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
        self._semaphore = eventlet.semaphore.Semaphore()
        self._semaphore_limit = eventlet.semaphore.Semaphore(value=self.rate)
        self._running = 0

    def __call__(self, func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            with self:
                return func(*args, **kwargs)
        return wrapped

    def __enter__(self):
        with self._semaphore:
            self._semaphore_limit.acquire(blocking=True, timeout=3)
            run_time = time.time()
            offset = len(self.schedule) - self.rate

            if offset >= 0 and run_time - self.limit < self.schedule[offset]:
                if self.callback:
                    sleeptime = run_time - self.schedule[offset] + self.limit
                    eventlet.spawn(self.callback, sleeptime)
                    eventlet.greenthread.sleep(sleeptime)
                run_time = self.schedule[offset] + self.limit
            self.schedule.append(run_time)
            return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        with self._semaphore:
            self._semaphore_limit.release()
            now = time.time()
            while self.schedule and self.schedule[0] < now - self.limit:
                self.schedule.popleft()
