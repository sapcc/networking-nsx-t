import os
if not os.environ.get('DISABLE_EVENTLET_PATCHING'):
    import eventlet
    eventlet.monkey_patch()
