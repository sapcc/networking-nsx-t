"""
This class is intended to collect the steps of calls execution
"""


class CallTracker(object):

    def __init__(self):
        """Empty initial collector"""
        self.collector = {}

    def init_track(self, track_id):
        """Initialize/Reinitialize a given track"""
        self.collector[track_id] = []

    def add_step(self, track_id, step_content):
        """Add a step to a given track"""
        self.collector[track_id] += [step_content]

    def get_steps(self, track_id):
        """Get the list of steps for a given track"""
        return self.collector[track_id]

    def compare_steps(self, track_id, steps_to_compare):
        """Compare the steps collected for a given track against the steps passed as argument"""

        # Get track steps
        track_steps = self.collector[track_id]

        # Check for valid lists of steps and lists lengths
        if steps_to_compare is None or track_steps is None or len(steps_to_compare) != len(track_steps):
            return False

        # Loop the lists
        for i in range(len(track_steps)):

            # Check for step match
            if track_steps[i] != steps_to_compare[i]:
                return False

        # No differences in the steps
        return True
