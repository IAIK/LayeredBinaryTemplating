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
    print(sc)
    keyboard.press_and_release(sc)
    time.sleep(WAIT_AFTER_EVENT_S)

def prepareEvents():
    # letter keys only 
    scan_codes = ["up arrow","down arrow","left arrow","right arrow"] 
    events = [(x, functools.partial(doKeyboardEvent, x))
              for x in scan_codes]
    events.append(("idle", doFakeEvent))
    return events
