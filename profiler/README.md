# Profiler

Install the utils for Windows with `install.bat` and on Linux with `./install.sh`

Run the profiler with a configuration from `profile_utils` folder on Linux as root to send the key events:
```
sudo ./event_fc_profiler.py ../profile_utils/fc_profiler_conf_linux_chrome.py --collect 20 --target_names chrome
```

Place your cursor to a target site for instance a website with a password field in Google Chrome, e.g., (`sample-target/index.html`).