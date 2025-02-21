"""
Synchronization - classes related concurrent execution scheduling and limits
"""
from typing import Callable, Union, Optional, List

import eventlet
eventlet.monkey_patch()

import networking_nsxv3.prometheus.exporter as EXPORTER
from networking_nsxv3.common.locking import LockManager
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


CBPARAMS = Union[str, dict]


class Runnable(object):

    def __init__(self, fnparams: CBPARAMS, fn: Callable[[CBPARAMS], None], priority=Priority.LOWEST):
        self.priority = priority
        self._fnparams = fnparams
        self._fn = fn

        # contradicting to code comments, we sometimes get a dictionary
        # as parameter for the callback. Some data from that
        # dictionary is then actually used, e.g. revision and resource id.
        # Not going to happen. Fixing that would require major
        # refactoring of the rpc and realizer objects. Not going to happen.
        #
        # Instead, in these cases we will still use the openstack id and the
        # name of the callback function to prevent parallel running of jobs.
        # But when a job is submitted to the Rerunner, it will keep track of the
        # dictionary contents if one exists and keep these for rerunning. So essentially
        # we create subjobs.
        # Realistically we need a better data structure than the active queue and Rerunner.

        # fnparams is a str for most of the callbacks:
        if isinstance(fnparams, str):
            self.idn = fnparams
        elif isinstance(fnparams, dict):
            self.idn = fnparams['id']
        else:
            self.idn = str(fnparams)
            LOG.warning('unexpected type %s for job parameters of %s', type(fnparams), fn.__name__)

        self._runcount = 0
        self._created = time.time()
        self._scheduled = None
        self._started = None
        self._jobdone = None
        self._rescheduled = None

    @property
    def identifier(self) -> tuple:
        return self.idn, self._fn.__name__

    def debugid(self)->str:
        return str((self.idn, self._fn.__name__, str(self._fnparams)))

    def set_scheduled(self):
        """ called when we submit the job to the worker pool """
        self._scheduled = time.time()
        self._started = None
        self._jobdone = None
        self._rescheduled = None

    def _set_start(self):
        """ called in our wrapper when we actually start fn """
        # we need to reset the other timings
        # because we use the same job for rerunning
        self._started = time.time()
        self._jobdone = None
        self._rescheduled = None
        self._runcount += 1

    def _set_done(self):
        """ called in our wrapper when fn returns """
        self._jobdone = time.time()
        self._rescheduled = None

    def set_rescheduled(self):
        """ called when the job is taken out of the rerun-queue """
        self._rescheduled = time.time()

    def get_statline(self) -> str:

        age = f"{time.time() - self._created:0.4f}"

        scheduled = '-'
        started = '-'
        runtime = '-'
        rescheduled = '-'

        if self._scheduled and self._created:
            scheduled = f"{self._scheduled - self._created:0.4f}"

        if self._started and self._scheduled:
            started = f"{self._started - self._scheduled:0.4f}"

        if self._jobdone and self._started:
            runtime = f"{self._jobdone - self._started:0.4f}"

        if self._rescheduled and self._jobdone:
            rescheduled = f"{self._rescheduled - self._jobdone:0.4f}"

        return (f"timings for job {self} - runcount: {self._runcount} age: {age} "
                f"scheduled: {scheduled} started: {started} runtime: {runtime} rescheduled: {rescheduled}")

    def execute(self):
        self._set_start()
        try:
            self._fn(self._fnparams)
        finally:
            self._set_done()

    def __repr__(self):
        # lets not just use the object id, maybe
        return str(self.identifier)

    def __eq__(self, other):
        """
        Note, the priority is not part of the comparison
        Thus if a runnable with higher priority is about to be
        added to the queue it will be rejected silently.
        To prevent starvation, the queue will update the priority of the
        existing element, in case it was lower than the item that was about to be added.
        """
        if isinstance(other, Runnable):
            return self._fnparams  == other._fnparams  and self._fn == other._fn
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        """ Order Runnable by their priority
        Only the passive queue is ordered by priority.
        The active queue is FiFo.
        """
        # if the priority is equal, we want to order
        # by creation time to handle oldest jobs first
        if self.priority == other.priority:
            return self._created < other._created # noqa

        return self.priority < other.priority


class UniqFiFoQueue(eventlet.queue.Queue):
    """
    A subclass of :class:`Queue` that maintains job order by insertion.

    Problem with the old approach:
    Jobs may starve in the active queue.

    - The internal sync run adds up to 20 "outdated" objects to the passive queue.
    - If space is available, jobs move from the passive to the active queue.
    - The active queue prioritizes jobs based on priority while enforcing uniqueness
      (determined by OpenStack ID and execution method).

    Issues:
    1. Job starvation – If high-priority jobs keep arriving and the agent is at full capacity,
       low-priority jobs may never get processed.
    2. Blocking of new high-priority jobs – Lower-priority jobs in the passive queue
       can prevent new high-priority jobs from being added due to the uniqueness constraint
       (see the `__eq__` method of the `Runnable` class).
    3. Adding a job with the **HIGHEST** priority does not
       guarantee execution in insertion order. See
       https://docs.python.org/3/library/heapq.html#priority-queue-implementation-notes
       for details.
    """

    def _init(self, maxsize):
        self.queue = collections.deque()

    def _put(self, item):
        if item not in self.queue:
            # Add item to the right side of the deque
            self.queue.append(item)
            self._put_bookkeeping()
        else:
            LOG.info("Not adding item %s to fifo queue, already present!", item)

    def _get(self):
        return self.queue.popleft()


class UniqPriorityQueue(eventlet.queue.Queue):

    def _init(self, maxsize):
        self.queue = []

    def _put(self, item):

        try:
            x = self.queue[self.queue.index(item)]
            # if the prio of the new item is higher (smaller value)
            # update the prio of the existing job and repair the heap
            if item.priority < x.priority:
                LOG.debug("Not adding item %s to prio queue, already present, but updating prio %s -> %s",
                          item, x.priority, item.priority)
                x.priority = item.priority
                heapq.heapify(self.queue)
            else:
                LOG.debug("Not adding item %s to prio queue, already present!", item)
            return
        except ValueError:
            # item is not in list
            pass

        # item not found, add it
        heapq.heappush(self.queue, item)
        self._put_bookkeeping()

    def _get(self):
        return heapq.heappop(self.queue)


class JobList():
    """ List of Runnables with the same identifier but different parameters

        In this datastructure we are keeping track of the jobs and their parameters for the JobRerunner,
        based on the identifier of the jib, which is telling us the type of job (callback name) and openstack id.

        There can be multiple similar jobs (same id, same method) but with different parameters, then parameter
        is a dict and not a string with only the OpenStack ID.

        These calls get a dict instead of a str: {enable, disable, update]_policy_logging, address_group_update

        In these cases this JobList will keep track of the jobs, merging jobs that are identical (same parameters)
        into one, to prevent unneccessary re-executions, but keeping them separate otherwise to not drop them.

        Note: Jobs with the same identifier will only compare equal if the parameters are identical as well, i.e.
        the dict or OpenStack ID is the same.


        add:

        When a job is added the _runnables list can be empty, then the job
        can run and we store it here for reference, with count 1.
        If the list is not empty the job can either already exist or it
        can be a job with different additional parameters.

        If the job already exists, we increase the counter, and do not allow it to run.
        If the job does not exist, we add it to the list with count = 1 and allow it to run.

        done:

        When a job is done, we will look at our list, and decrease the counter.
        If the counter is 0, the job was not submitted a second time, and we can remove
        it from the list.
        If the counter is not 0, the job was requested to run again, and we keep it in the
        list with the updated counter.

        done will then choose a job from the list, that is supposed to run again,
        remove it from the list and return it to the JobRerunner.

        This might be exactly the same job that was just finished (if it needs rerunning) or
        it could be a different one, that is: same openstack id, different parameter dict.

        For now we will choose the oldest one based on age, which should be the same job that
        was just done, but we might want to change that so we use a helper function for that
        for now in the POC. The current helper uses pop() so our list basically is a FiFo.
    """

    def __init__(self):
        self._job_identifier: Optional[str] = None
        self._runnables: List[tuple[int, Runnable]] = []

    def __len__(self):
        return len(self._runnables)

    @property
    def size(self):
        return sum(count for count, _ in self._runnables)

    def empty(self):
        return self.size == 0

    def __repr__(self):
        return f"Joblist: {self._job_identifier}, len={len(self)}, {self._runnables}"

    def add(self, job:Runnable)->bool:
        """ add a job to the list, must share identifier

        Jobs with the same identifier (that is OpenStack ID and callback name) can still
        have different additional parameters. This is the case for the policy logging api
        calls, where the argument is not just a OpenStack ID but a dictionary.
        This method adds those jobs to this list, but checks for those extra parameters.

        See Class documentation for more details.

        returns True if the same job was not present yet, False if one already existed
        """

        if self._job_identifier is not None:
            if job.identifier != self._job_identifier:
                raise ValueError("Can only add jobs of same type to a JobList")
        else:
            self._job_identifier = job.identifier

        # search through our list and update the counter or append the job:
        for index, (count, existing_job) in enumerate(self._runnables):
            if job == existing_job:
                if count < 1:
                    # fix the list, otherwise we would never run that job.
                    LOG.error("Joblist counter for job %s is %d, indicating job should have been removed.", job, count)
                    count = 0
                count += 1
                self._runnables[index] = (count, existing_job)
                if count == 1:
                    # failsafe:
                    # return True if this is the first time the job has been added,
                    # only happens at this point if our bookkeeping was off.
                    return True
                return False

        # No match found, this is the first of its kind, we can run it.
        # note that a job that gets re-executed will be removed from
        # the list (keeping others with same identifier but different parameters)
        # so when it returns it will be the only one of its kind and
        # can run. after it is finished a different one will be returned by 'done'.
        self._runnables.append((1, job))
        return True

    def _runnable_is_done(self, job:Runnable):
        """ search through our list and update the counter or remove the job """
        for index, (count, existing_job) in enumerate(self._runnables):
            if job == existing_job:
                # we do not need this job with this parameters again, it is done,
                # so we remove it from the list.
                # Note: the list might not be empty!
                LOG.debug("Job %s is done, updating JobList, request count was: %d", job.debugid(), count)
                count -= 1
                if count <= 0:
                    if count < 0:
                        LOG.warning("Job count in JobList was %d for %s", count, job.debugid())
                    del self._runnables[index]
                    return
                # leave job in the list, so it will get retrieved again later.
                # when retrieving we use pop() so the list gets cleared then.
                self._runnables[index] = (count, existing_job)
                return

        # we should never mark a job done, that was not added in the first place,
        # if its not in the list, something is wrong
        LOG.error("Runnable %s was not found in Joblist, trying to mark it done!", job)


    def _runnable_pop_next(self) -> Optional[Runnable]:
        """ Find the next job to run and remove it from the list,
            or return None if there is None to run.
        """
        if not self._runnables:
            return None
        # no job should currently be running, because we are in the "done" part of the
        # workflow. So we can choose any job we like, remove it from the list and run it.
        # when that job returns and needs no re-execution it will be removed from the list,
        # and we will not pop it here again, so the next one in line will be returned.
        # we always append to our list, so we can just pop the first one here and get the oldest.
        count, job = self._runnables.pop()
        LOG.debug("found job to run next with %d rerun requests open: %s", count, job)
        return job

    def done(self, job:Runnable)->Optional[Runnable]:
        """ Mark a job as done and return next job to run.

        Removes the job from the list, if there are jobs left in the list, will return the next one to run.

        returns a job to run next, or None if there are no jobs left to run.
        """
        if self._job_identifier is not None:
            if job.identifier != self._job_identifier:
                raise ValueError("Can only remove jobs of same type from a JobList")

        self._runnable_is_done(job)
        return self._runnable_pop_next()

    def get_count(self, job):
        """ Returns how often this specific job had been requested to run while already running """

        if self._job_identifier is not None:
            if job.identifier != self._job_identifier:
                LOG.error('Joblist was queried for wrong job type - got job "%s", expected identifier "%s"', job, self._job_identifier)
                return 0

        for count, existing_job in self._runnables:
            if job == existing_job:
                return count

        return 0


class JobRerunner():
    """ Thread save data structure to reschedule jobs when they are already running

    When a job is retrieved from the active queue and already running in a worker thread,
    there is a chance that another job for the same object is added to the active
    queue and also started in a worker. To prevent race conditions, the worker threads
    will use a lock to prevent two jobs running on the same objects, but this leads to
    blocking of each of the affected workers, which degrades performance and also re-executes
    the jobs unnecessarily often.

    To prevent this, we use this JobRerunner:

    In this class we keep track of all jobs currently running in the workers.

    When taking a new job from the active queue, we check if this job is
    already running. If this is not the case, we will add it to our bookkeeping
    here, and it will be sent to a worker, wrapped in a function that will call
    the JobRunner on job completion to update the bookkeeping.

    If we find the job already running, the new job will be dropped, but a counter
    for the job will be increased to mark the job for re-execution once its done,
    in case a change to the object had occured while the worker was running.

    When a worker is done with a job, it will notify us, and we can either
    remove the id from our bookkeeping or, if a new job was added in the meantime,
    mark it as ready for re-execution. Note that a job will intentionally only be
    re-executed once, independently of how often it was added while a worker was
    already running it.

    Before taking a new job from the active queue in the runner, we first check in
    the JobRerunner for a ready job, making sure that these jobs are prioritized
    to pick up changes quickly.
    """

    _lname_running = 'JobRerunner-running'
    _lname_torerun = 'JobRerunner-torerun'

    def __init__(self):
        self._running: collections.defaultdict[(int, str),JobList] = collections.defaultdict(JobList)
        self._to_rerun: collections.deque[Runnable] = collections.deque()

    def get_rerunnable(self) -> Runnable:
        # Let's also use the LockManager that is used for locking
        # in the code already. A simpler lock might do fine, but
        # for the LockManager we know it is working.

        with LockManager.get_lock(self._lname_torerun):
            try:
                job = self._to_rerun.popleft()
                job.set_rescheduled()
                LOG.info("JobRerunner (about to rerun) %s", job.get_statline())
            except IndexError:
                job = None
                LOG.debug("JobRerunner had no rerunnable job")

        return job

    def job_done(self, job: Runnable):
        """ Marks job as done, update bookkeeping and if needed add job to the queue for re-execution """
        LOG.debug("JobRerunner job_done called for %s", job)

        with LockManager.get_lock(self._lname_running):

            joblist: JobList = self._running[job.identifier]
            next_job = None
            try:
                next_job = joblist.done(job)
            except Exception as e:
                LOG.error("Error getting next job after a job was done: %s", e)

            if joblist.empty():
                try:
                    del self._running[job.identifier]
                except KeyError:
                    # should never happen, we just fetched it above
                    pass
            else:
                # TODO(mutax): make debug after nsx-t issues solved
                LOG.info("After job done %s", joblist)

            if not next_job:
                # TODO(mutax): make debug after nsx-t issues solved
                LOG.info("JobRerunner (done, no reruns requested) %s", job.get_statline())
            else:
                # we got a job to rerun from our helper
                # TODO(mutax): make debug after nsx-t issues solved
                LOG.info("JobRerunner (done, got rerun) done: %s next: %s", job.get_statline(), next_job.get_statline())
                with LockManager.get_lock(self._lname_torerun):
                    self._to_rerun.append(next_job)

    def add_job(self, job: Runnable) -> bool:
        """ Add job to list of jobs running/to be started or mark it for re-execution

        returns True if the job is currently not running and should
        be scheduled next / added to the workers.

        returns False if the job is already running and was marked for re-execution

        """
        with LockManager.get_lock(self._lname_running):
            joblist:JobList = self._running[job.identifier]

            if joblist.add(job):
                # no job running, we can run the job
                LOG.debug("JobRerunner no identical job is currently running, can start %s", job)
                return True
            else:
                count = joblist.get_count(job)
                LOG.debug("JobRerunner job %s already running, marked for rescheduling, count: %d ", job, count)

            sum = 0
            for identifier, joblist in self._running.items():
                sum += joblist.size
                LOG.debug("JobRerunner stat: job %s is running, submission count: %d", identifier, joblist.size)

        # TODO(mutax): make debug after nsx-t issues solved
        LOG.info("JobRerunner stat: %d jobs tracked, total submission count: %d, ready for re-exection: %d",
                 len(self._running), sum, len(self._to_rerun))

        return False


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
        self._active = UniqFiFoQueue(maxsize=active_size)
        self._passive = UniqPriorityQueue(maxsize=passive_size)
        self._workers = eventlet.greenpool.GreenPool(size=workers_size)
        self._idle = workers_size
        self._state = "not started"
        self._rerunner = JobRerunner()

    def run(self, priority, ids, fn):
        """ Submit a job with priority

        Note: the second parameter apparently sometimes is a dictionary, in contrast
              to the documentation in the code!
              Fixing this would requires too much refactoring at the moment -- mutax

        Keyword arguments:
        priority -- job priority of type Priority.class
        ids -- list of OpenStack-IDs (identifiers) that will be passed to the 'fn'
               OR list of dictionaries(!) of OpenStack objects (containing their id)
        fn -- a function about to be executed by the runner with an argument ID
        """
        if self._state != "started":
            report = MESSAGE.format("Skipping", ids, priority.name, fn.__name__)
            LOG.warn("Runner is in State:%s .%s", self._state, report)
            return

        for jid in ids:
            try:
                LOG.info(MESSAGE.format("About to enqueue", jid, priority.name, fn.__name__))

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
                pulled_from_queue = False
                job = self._rerunner.get_rerunnable()
                if not job:
                    job = self._active.get(block=True, timeout=TIMEOUT)
                    pulled_from_queue = True

                # check if we are allowed to run it,
                # if yes mark it as running and spawn it
                if self._rerunner.add_job(job):
                    LOG.info(MESSAGE.format("Processing", job.idn, Priority(job.priority).name, job))

                    # ideally we would be able to add a callback to the
                    # greenthread, but this is hidden in the pool, so
                    # let's wrap the function once more.
                    def wrap(rerun: JobRerunner, ajob: Runnable):
                        ajob.execute()
                        rerun.job_done(ajob)

                    job.set_scheduled()
                    self._workers.spawn(wrap, self._rerunner, job)

                if pulled_from_queue:
                    self._active.task_done()
            except eventlet.queue.Empty:
                LOG.info("No activity for the last {} seconds.".format(TIMEOUT))
                LOG.info("Sizes Queue[Active=%s, Passive=%s], Jobs=%s",
                    self.active(), self.passive(), self._workers.running())
            except Exception as err:
                # Continue on error, or else the agent operation would stop
                LOG.exception("Unknown agent error: %s", err)
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
