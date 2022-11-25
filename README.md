# Layered Binary Templating Attacks
PoC Repo of CVE-2022-2612.
Side-channel information leakage in Keyboard input in Google Chrome prior to 104.0.5112.79 can be recovered via the page cache attack and cache attack.

Use the `profiler` to profile your target applications.
This will create profiles based on the page activity of the processes on Windows and Linux.
Read the descriptions in the subfolders how to run the experiments.
`profile_utils` contains profiles, a useful `index.html` for browsers and utils for the profiling.
Use the `cache_line_extractor` to extract the key-dependent cache lines directly from Chromium-based applications.
The `cache_based_keylogger` can be used to spy on Keystrokes in susceptible applications.

See a demonstration of the attack here:
[here](https://youtu.be/hUxaCEZMOF4)

You can find the paper [here](https://martinschwarzl.at/media/files/layered.pdf).