#!/usr/bin/env bash

# old style
#PYMODULE_PATH=$(python3 -m site --user-site)
#mkdir -p $PYMODULE_PATH
#cp -r packages/* $PYMODULE_PATH/

# new style using pip
sudo -H python3 -m pip install packages/fctools
sudo -H python3 -m pip install packages/vmtools