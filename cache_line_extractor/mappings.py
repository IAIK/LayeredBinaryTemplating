#!/usr/bin/python3

import sys,os
import mmap
import json

offsets = {
    "a":b'\x00KeyA\x00',
    "b":b'\x00KeyB\x00',
    "c":b'\x00KeyC\x00',
    "d":b'\x00KeyD\x00',
    "e":b'\x00KeyE\x00',
    "f":b'\x00KeyF\x00',
    "g":b'\x00KeyG\x00',
    "h":b'\x00KeyH\x00',
    "i":b'\x00KeyI\x00',
    "j":b'\x00KeyJ\x00',
    "k":b'\x00KeyK\x00',
    "l":b'\x00KeyL\x00',
    "m":b'\x00KeyM\x00',
    "n":b'\x00KeyN\x00',
    "o":b'\x00KeyO\x00',
    "p":b'\x00KeyP\x00',
    "q":b'\x00KeyQ\x00',
    "r":b'\x00KeyR\x00',
    "s":b'\x00KeyS\x00',
    "t":b'\x00KeyT\x00',
    "u":b'\x00KeyU\x00',
    "v":b'\x00KeyV\x00',
    "w":b'\x00KeyW\x00',
    "x":b'\x00KeyX\x00',
    "y":b'\x00KeyY\x00',
    "z":b'\x00KeyZ\x00',
    "0":b'\x00Digit0\x00',
    "1":b'\x00Digit1\x00',
    "2":b'\x00Digit2\x00',
    "3":b'\x00Digit3\x00',
    "4":b'\x00Digit4\x00',
    "5":b'\x00Digit5\x00',
    "6":b'\x00Digit6\x00',
    "7":b'\x00Digit7\x00',
    "8":b'\x00Digit8\x00',
    "9":b'\x00Digit9\x00',
    # "0":b'Numpad0\x00',
    # "1":b'Numpad1\x00',
    # "2":b'Numpad2\x00',
    # "3":b'Numpad3\x00',
    # "4":b'Numpad4\x00',
    # "5":b'Numpad5\x00',
    # "6":b'Numpad6\x00',
    # "7":b'Numpad7\x00',
    # "8":b'Numpad8\x00',
    #"9":b'Numpad9\x00',
    #"ENTER":b'Enter\x00',
    #"ESC":b'Escape\x00',
    #"BCKSPACE": b'Backspace\x00',
    #"TAB": b'Tab\x00',
    # "-": b'Space\x00',
    # "=": b'Minus\x00',
    # "=": b'Equal\x00',
    # "SHL": b'ShiftLeft\x00'
    #"[": b'BracketLeft\x00',
    #"]": b'BracketRight\x00',
    #";": b'Semicolon\x00',
    #"\"": b'Quote\x00',
    #"`": b'Backquote\x00',
    #",": b'Comma\x00',
}

if len(sys.argv) != 2:
    print("python3 mappings.py <file-to-scan>")
    os._exit(1)

res_mappings_cl = {}
res_mappings_page = {}

with open(sys.argv[1],"r") as f:
    mm = mmap.mmap(f.fileno(),0, access=mmap.ACCESS_READ)
    for k,v in offsets.items():
        offset = mm.find(v) 
        res_mappings_cl[k] = offset
        res_mappings_page[k] = offset & ~(0xfff)
        print(f"{hex(offset)}",end=",")

with open(f'config_{os.path.basename(sys.argv[1])}_cl.json', 'w') as outfile:
    json.dump([res_mappings_cl], outfile)
  
# Using a JSON string
with open(f'config_{os.path.basename(sys.argv[1])}_page.json', 'w') as outfile:
    json.dump([res_mappings_cl], outfile)