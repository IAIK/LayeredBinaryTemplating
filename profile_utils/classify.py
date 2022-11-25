#!/usr/bin/env python3
import argparse
import json
from typing import Mapping
import numpy as np
import sys
from fctools import fc_hit_classify
import pdb


EVENTS_TO_GERMAN_KEYBOARD = ["^", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "ß", "`", "BACK",
    "TAB", "q", "w", "e", "r", "t", "z", "u", "i", "o", "p", "ü", "+", "RETURN", 
    "CAPITAL", "a", "s", "d", "f", "g", "h", "j", "k", "l", "ö", "ä", "#",
    "LSHIFT", "<", "y", "x", "c", "v", "b", "n", "m", ",", ".", "-", "RSHIFT",
    "LCONTROL", "LMENU", "SPACE"]


def raCornersToString(event_mapping):
    string = ""
    if not "evaluate_ra_corners" in event_mapping:
        return None

    if event_mapping["evaluate_ra_corners" ] == 0:
        string += "{:x}".format(event_mapping["ra_corner_pages_ch_ratios"][0][0])
        string += ", " 
    elif event_mapping["evaluate_ra_corners" ] == 1:       
        string += ", "
        string += "{:x}".format(event_mapping["ra_corner_pages_ch_ratios"][1][0])  
    elif event_mapping["evaluate_ra_corners" ] == 2:
        string += "{:x}".format(event_mapping["ra_corner_pages_ch_ratios"][0][0])
        string += ", "
        string += "{:x}".format(event_mapping["ra_corner_pages_ch_ratios"][1][0])
    elif event_mapping["evaluate_ra_corners" ] == -1:
        return None

    return string

def printResults(sample_time, detected_events):
    event_string_raw = ",".join([str(x) for x in detected_events])
    event_string_german_keyboard = ",".join([EVENTS_TO_GERMAN_KEYBOARD[x] for x in detected_events])
    # print raw event numbers + german key representation
    print("{};{};{}".format(sample_time, event_string_raw, event_string_german_keyboard))


parser = argparse.ArgumentParser(description="Evaluates page cache hit data.")
parser.add_argument("training_results", type=str, metavar=("TRAINING_RESULTS_PATH"),
                      help="loads training results from a json file")
parser.add_argument("--attack_conf", type=str, metavar=("PATH"),
                      help="creates attack configuration file")
parser.add_argument("--verbose", action="store_true", help="verbose print")
args = parser.parse_args()

# instantiate classifier
classifier = fc_hit_classify.Classifier(args.training_results)

# creates attack configuration file out of profile
if args.attack_conf:
    classifier.createAttackConfig(args.attack_conf)
    exit(0)

if args.verbose:
    # print mappings in a nice way
    file_to_events = classifier.training_results_
    for file in file_to_events.keys():
        print(file + ": ")
        for poffset in sorted(file_to_events[file].keys()):
            print("{:x} -> {}".format(poffset, file_to_events[file][poffset]["event_group_labels"]), end="")
            ra_corners_string = raCornersToString(file_to_events[file][poffset])
            if ra_corners_string is not None:
                print(" (supporting ra corner pages: {})".format(ra_corners_string), end="")
            print("")
        print("")

while True:
    sample = classifier.classifyNextStdin()
    if sample is None:
        exit(0)
    # process + print results
    if len(sample[1]) != 0:
        printResults(sample[0], sample[1])
