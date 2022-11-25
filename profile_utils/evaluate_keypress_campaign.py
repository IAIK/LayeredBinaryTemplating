#!/usr/bin/env python3

import argparse
import numpy as np
import json


# NOTE has to be right else entropy calculation is wrong
KEY_COUNT = 57
SCAN_CODES = [0x29, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 
    0x3a, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2b, 
    0x2a, 0x56, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x1d, 0x38, 0x39]


def parseLog(log_path, force_event_integer = False):
    parsed = []
    with open(log_path, "r") as file:
        while True:
            line = file.readline()
            if line == "":
                break
            tokens = line.split(";")
            events = [ int(x) for x in tokens[1].split(",") ]
            events = events[0] if force_event_integer else set(events)
            parsed.append((float(tokens[0]), events))
    return parsed 


parser = argparse.ArgumentParser(
    description="Evaluate a keypress campaign.")
parser.add_argument("simulated_keypress_log", type=str, metavar=("SIMULATED_KEYPRESS_LOG_PATH"), 
    help="path to the log of the simulated keypresses")
parser.add_argument("detected_keypress_log", type=str, metavar=("DETECTED_KEYPRESS_LOG_PATH"), 
    help="path to the log of the detected keypresses")
parser.add_argument("--save", type=str, metavar=("RESULTS_SAVE_PATH"), 
    help="save results to this path")
args = parser.parse_args()


key_evaluation_results = {}
# prepare
for event in range(KEY_COUNT + 1):
    key_evaluation_results[event] = {
        "classification": {
            "true_positive": 0,
            "false_positive": 0,
            "event_group_sizes": []
        },
        "simulations": {
            "count": 0
        }
    }
simulated_keypresses = parseLog(args.simulated_keypress_log, True)
detected_keypresses = parseLog(args.detected_keypress_log)

keypress_period = simulated_keypresses[1][0] - simulated_keypresses[0][0]

# Evaluation Method 
# we divide the time into slots equal to the time between the simulated keypresses
# then we determine the precision and recall counts for the simulated keypresses by
# tracking the right and wrong classifications:
# right classification -> ONE or MULTIPLE detected event groups in slice which all contain the target class
# wrong classification -> either zero events (except for IDLE event), 
# or ONE of the found event groups does not contain the target class
# additionally the size of the detected group is tracked 
# (for later entropy reduction calculation)
detected_keypress_i = 0
for (i, simulated_keypress) in enumerate(simulated_keypresses):
    next_simulated_keypress = simulated_keypresses[i + 1] if i < len(simulated_keypresses) - 1 else None


    #print("Simulated Event: {}".format(simulated_keypress[1]))
    slice_keypresses = 0
    slice_events_group_sizes = []
    slice_wrong_events = set()
    while detected_keypress_i < len(detected_keypresses):
        detected_keypress = detected_keypresses[detected_keypress_i]

        # detected keypress is before current simulated one
        # forward to next detected event (for beginning)
        if detected_keypress[0] < simulated_keypress[0]:
            #print("Skipping")
            detected_keypress_i += 1
            continue
        # already in next slice
        if(next_simulated_keypress is not None and
            detected_keypress[0] > next_simulated_keypress[0]):
            # current slice processed
            break
        # early exit at end (the manual stopping would introduce errors)
        if next_simulated_keypress is None and detected_keypress[0] - simulated_keypress[0] > keypress_period:
            break

        #print("Detected Events: {}".format(detected_keypress[1]))
        # track wrong classification results
        if simulated_keypress[1] not in detected_keypress[1]:
            slice_wrong_events = slice_wrong_events.union(detected_keypress[1])
        slice_events_group_sizes.append(len(detected_keypress[1]))
        slice_keypresses += 1
        detected_keypress_i += 1

    # evaluate
    key_evaluation_results[simulated_keypress[1]]["simulations"]["count"] += 1
    # keypress detected -> could be right
    if slice_keypresses > 0:
        # all detected keypress event groups containted simulated keypress -> correct
        if len(slice_wrong_events) == 0:
            # true positive of simulated class
            key_evaluation_results[simulated_keypress[1]]["classification"]["true_positive"] += 1
            key_evaluation_results[simulated_keypress[1]]["classification"]["event_group_sizes"].append(np.mean(slice_events_group_sizes))
            #print("{} TP".format(simulated_keypress[1]))
        # (parts of) detected events were wrong
        else:
            for event in slice_wrong_events:
                key_evaluation_results[event]["classification"]["false_positive"] += 1
                #print("{} FP".format(event))

    # no keypress (== idle event) -> could be right if idle event was simulated
    # slice_keypresses == 0
    else:
        if simulated_keypress[1] == KEY_COUNT:
            # true positive of IDLE event
            key_evaluation_results[KEY_COUNT]["classification"]["true_positive"] += 1
            # for idle just append 1 in case its right
            key_evaluation_results[KEY_COUNT]["classification"]["event_group_sizes"].append(1)
            #print("{} TP".format(KEY_COUNT))
        else:
            # false positive of IDLE event
            key_evaluation_results[KEY_COUNT]["classification"]["false_positive"] += 1
            #print("{} FP".format(KEY_COUNT))

# calculate metrics for every event
attack_new_entropy = 0
for event in sorted(key_evaluation_results.keys()):
    result = key_evaluation_results[event]
    # calculate precision and recall
    result["classification"]["precision"] = -1 if (result["classification"]["true_positive"] + result["classification"]["false_positive"]) == 0 else result["classification"]["true_positive"] / (result["classification"]["true_positive"] + result["classification"]["false_positive"])
    result["classification"]["recall"] = result["classification"]["true_positive"] / result["simulations"]["count"]
    # calculate mean and std of event group size
    if len(result["classification"]["event_group_sizes"]) != 0:
        result["classification"]["event_group_size_mean"] = float(np.mean(result["classification"]["event_group_sizes"]))
        result["classification"]["event_group_size_std"] = float(np.sqrt(np.var(result["classification"]["event_group_sizes"])))
    else:
        result["classification"]["event_group_size_mean"] = -1
        result["classification"]["event_group_size_std"] = -1

    # print results
    print("Simulated keypress scancode: {}".format("0x{:x}".format(SCAN_CODES[event]) if event < KEY_COUNT  else "IDLE"))
    print("Precision: {} Recall: {}".format(result["classification"]["precision"], result["classification"]["recall"]))
    print("Mean event group size: {} Standard deviation event group size: {}".format(result["classification"]["event_group_size_mean"], result["classification"]["event_group_size_std"]))

results = {
    "keys": key_evaluation_results,
}

if args.save:
    with open(args.save, "w") as file:
        file.write(json.dumps(results, indent=4))