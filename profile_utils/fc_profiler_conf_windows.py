import keyboard
import time
import functools
import random

# some blacklisted libraries which showed unstable or unwanted results
FILE_BLACKLIST_REGEX = [
#    r"/usr/share/fonts/.*", 
#    r"/usr/lib/x86_64-linux-gnu/libxcb\.so\.1\.1\.0", 
#    r"/usr/lib/x86_64-linux-gnu/libX11-xcb.so.1.0.0",
#    r"/opt/google/chrome/icudtl\.dat",
#    r"/usr/lib/x86_64-linux-gnu/libevdev\.so\.2\.3\.0",
#    r"/lib/x86_64-linux-gnu/libm-2.31.so"
]
# optionally blacklisted pages of files
# "file": [21,12,34]
FILE_PAGE_BLACKLIST = {
#    "/opt/google/chrome/chrome": [0x1257],
#    "/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0.6400.6" : [0x85],
#    "/usr/lib/x86_64-linux-gnu/libgdk-3.so.0.2404.16": [0xbf],
#    "/usr/share/glib-2.0/schemas/gschemas.compiled": [0x1c],
#    "/usr/lib/x86_64-linux-gnu/libX11.so.6.3.0": [0x8d, 0x8e]
} 

# wait a bit after a event was triggered to allow all accesses to happen
# we do not want to wait too long as this might slow down the attack 
WAIT_AFTER_EVENT_S = 0.025
# wait longer in case of idle event 
# (we also want to catch less frequent periodic page accesses "noise")
IDLE_EVENT_WAIT_S = 0.025

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

# dirty hack because of programming error in keyboard library
keyboard._winkeyboard._setup_name_tables()

def doFakeEvent():
    time.sleep(IDLE_EVENT_WAIT_S)

def doKeyboardEvent(sc):
    keyboard.send(sc)
    time.sleep(WAIT_AFTER_EVENT_S)

def prepareEvents():
    # main part of keyboard - except extended scancode keys
    scan_codes = [0x29, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 
        0x3a, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2b, 
        0x2a, 0x56, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 
        0x1d, 0x39] #0x38, 0x39]
    events = [("sc_" + hex(x), functools.partial(doKeyboardEvent, x))
              for x in scan_codes]
    events.append(("fake", doFakeEvent))
    return events
