#!/usr/bin/env python3

from pynput.mouse import Button, Controller
import random
import time


SLEEP_TIME_S = 0.001


mouse = Controller()
x_dim, y_dim = (1920, 1080)

while True:
    mouse.position = (random.randint(0, x_dim), random.randint(0, y_dim))
    time.sleep(SLEEP_TIME_S)
