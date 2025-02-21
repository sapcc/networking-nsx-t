from oslo_log import log as logging
from oslo_config import cfg
from neutron.tests import base

LOG: logging.KeywordArgumentAdapter = logging.getLogger(__name__)


def set_logging_levels():
    cfg.CONF.set_override("default_log_levels", [
        'networking_nsxv3.common.synchronization=WARNING',
    ])


class TestAgentRealizerScheduling(base.BaseTestCase):
    def setUp(self):
        super().setUp()

        set_logging_levels()
        logging.setup(cfg.CONF, "demo")

    def test_rerunner_simple(self):
        from networking_nsxv3.common.synchronization import JobRerunner, Runnable

        rerunner = JobRerunner()

        def nop(item):
            LOG.debug("nop(%s) called", item)

        # add some jobs
        for some_id in range(100):
            job = Runnable(str(some_id), nop)
            ret = rerunner.add_job(job)
            self.assertTrue(ret)

        # mark them all done -- note that because
        # if and fn-name are the same, this should match,
        # although creating new jobs
        for some_id in range(100):
            job = Runnable(str(some_id), nop)
            rerunner.job_done(job)

        # no job was added twice, so no job should be re-executed
        self.assertEqual(rerunner.get_rerunnable(), None)

    def test_rerunner_rerun(self):
        from networking_nsxv3.common.synchronization import JobRerunner, Runnable

        rerunner = JobRerunner()

        def nop(item):
            # should never happen
            LOG.error("nop(%s) called", item)

        # add some jobs
        for some_id in range(100):
            job = Runnable(str(some_id), nop)
            ret = rerunner.add_job(job)
            self.assertTrue(ret)

        # add them again, twice
        for some_id in range(100):
            job = Runnable(str(some_id), nop)
            ret = rerunner.add_job(job)
            self.assertFalse(ret)
            ret = rerunner.add_job(job)
            self.assertFalse(ret)

        # mark them all done, then expect them
        # all to be returned once in get_rerunnable,
        # although added twice again above
        for some_id in range(100):
            job = Runnable(str(some_id), nop)
            rerunner.job_done(job)

        alljobs = []
        while job := rerunner.get_rerunnable():
            alljobs.append(job)

        # each job should be returned only once
        self.assertEqual(len(alljobs), 100)

    def test_fifoqueue(self):
        from networking_nsxv3.common.synchronization import UniqFiFoQueue
        from eventlet.queue import Empty
        queue = UniqFiFoQueue()

        for i in range(10):
            queue.put(i)
            queue.put(i)
        for i in range(20, 10, -1):
            queue.put(i)

        try:
            ret = []
            for i in range(200):
                item = queue.get(block=False)
                ret.append(item)
        except Empty:
            pass

        expected = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11]
        self.assertEqual(expected, ret)

    def test_prioqueue(self):
        from networking_nsxv3.common.synchronization import UniqPriorityQueue
        from eventlet.queue import Empty
        queue = UniqPriorityQueue()

        class PrioItem:

            def __init__(self, uid, prio):
                self.priority = prio
                self.uid = uid

            def __lt__(self, other):
                if self.priority < other.priority:
                    return -1
                elif self.priority > other.priority:
                    return 1
                return 0

            def __eq__(self, other):
                return self.uid == other.uid

            def __repr__(self):
                return f"PrioItem({self.uid},{self.priority})"

        for i in range(10):
            queue.put(PrioItem(i, 5))
            queue.put(PrioItem(i, 1))
        for i in range(15, 5, -1):
            queue.put(PrioItem(i, 4))

        try:
            ret = []
            for i in range(200):
                item = queue.get(block=False)
                ret.append((item.uid, item.priority))
        except Empty:
            pass

        # the first 6 items should have the lowest prio,
        # then 10 with the highest, prio 5 should never be seen
        self.assertEqual([4] * 6, [prio for uid, prio in ret[:6]])
        self.assertEqual([1] * 10, [prio for uid, prio in ret[6:]])

        # each item should be present only once.
        # because sorting is not stable, we need to sort the uids
        # to compare
        ret = sorted([uid for uid, prio in ret])
        self.assertEqual(list(range(16)), ret)

    def test_runnable_timings(self):
        import time
        from unittest.mock import Mock
        from networking_nsxv3.common.synchronization import Runnable

        callback = Mock()
        callback.__name__ = 'callback'

        job = Runnable("Testjob 23", callback)

        self.assertIn('runcount: 0', job.get_statline())
        job.execute()
        self.assertIn('runcount: 1', job.get_statline())
        time.sleep(.15)

        job.set_rescheduled()
        self.assertNotIn('rescheduled: -', job.get_statline())
        self.assertNotIn('runtime: -', job.get_statline())

        callback.assert_called()
