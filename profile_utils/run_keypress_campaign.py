#!/usr/bin/env python3

import argparse
import keyboard
import time
import functools
import random
import platform

if platform.system() == "Windows":
    # dirty hack because of programming error in keyboard library
    keyboard._winkeyboard._setup_name_tables()


def doFakeEvent(access_period):
    time.sleep(access_period)

def doKeyboardEvent(sc, access_period):
    keyboard.press(sc)
    keyboard.release(sc)
    time.sleep(access_period)

def prepareKeyEvents(access_period):
    # main part of keyboard - except extended scancode keys
    scan_codes = [0x29, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
    	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 
        0x3a, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2b, 
        0x2a, 0x56, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x1d, 0x38, 0x39]
    events = [("sc_" + hex(x), functools.partial(doKeyboardEvent, x, access_period))
              for x in scan_codes]
    events.append(("fake", functools.partial(doFakeEvent, access_period)))
    return events


parser = argparse.ArgumentParser(
    description="Runs a keypress campaign.")
parser.add_argument("period_ms", type=int, metavar=("PERIOD_MS"), help="keypress period in ms")
parser.add_argument("samples", type=int, metavar=("SAMPLES"), help="amount of samples per different keypress")
parser.add_argument("--verbose", action="store_true", help="verbose print")
args = parser.parse_args()

events = prepareKeyEvents(float(args.period_ms) / 1000)

if args.verbose:
    print("Simulating {} keys.".format(len(events) - 1))
    print("Starting in 15s...")
time.sleep(15)
for s in range(args.samples):
    for event_i, event in random.sample(list(enumerate(events)), len(events)):
        keypress_timestamp_us = int(time.time_ns() / 1000)
        event[1]()
        print("{};{}".format(keypress_timestamp_us, event_i))
