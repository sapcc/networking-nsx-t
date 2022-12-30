
import os
import sys
import logging

LOG = logging.getLogger(__name__)

cmd = ["security", "find-generic-password",  "-a $USER -s openstack -w 2>/dev/null"]

def set_as_openstack_env():
    if sys.platform == "darwin":
        # OS X
        _cmd = ' '.join(cmd)
        p = os.popen(_cmd)
        pw = p.read()
        p.close()
        if not pw:
            LOG.warning("Please check if password can be loaded with the command  - security", "find-generic-password",  "-a $USER -s openstack -w 2>/dev/null ")

        os.environ["OS_PASSWORD"] = pw.strip()
    else:
        LOG.warning("Did not load platform - Make sure OS_PASSWORD is set")


