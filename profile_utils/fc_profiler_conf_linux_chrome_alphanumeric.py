import keyboard
import time
import functools
import random

# some blacklisted libraries which showed unstable or unwanted results
FILE_BLACKLIST_REGEX = [
    r"/usr/share/fonts/.*"
]
FILE_WHITELIST_REGEX = [
    r"/opt/google/chrome/chrome"
]
# optionally blacklisted pages of files
# "file": [21,12,34]
FILE_PAGE_BLACKLIST = {
    "/opt/google/chrome/chrome": [ 0x14bc ]
} 

# wait a bit after a event was triggered to allow all accesses to happen
# we do not want to wait too long as this might slow down the attack 
WAIT_AFTER_EVENT_S = 0.025
# wait longer in case of idle event 
# (we also want to catch less frequent periodic page accesses "noise")
IDLE_EVENT_WAIT_S = 30

# custom event sequence generator used during sampling
# default is random shuffling of the events for each sample
def collectEventGenerator(events, len, samples):
    same_samples = int(samples / 2)
    random_samples = samples - same_samples

    # random 
    for _ in range(random_samples):
        for event in random.sample(events, len):
            yield event
    
    # same sequence
    for event_id in range(len):
        for _ in range(same_samples):
            yield events[event_id]
CUSTOM_COLLECT_EVENT_GENERATOR = collectEventGenerator

def doFakeEvent():
    time.sleep(IDLE_EVENT_WAIT_S)

def doKeyboardEvent(sc):
    keyboard.send(sc)
    time.sleep(WAIT_AFTER_EVENT_S)

def prepareEvents():
    # letter keys only 
    scan_codes = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 
          0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 
          0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32]
    events = [("sc_" + hex(x), functools.partial(doKeyboardEvent, x))
              for x in scan_codes]
    events.append(("idle", doFakeEvent))
    return events
