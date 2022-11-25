from vmtools.nt import *

#convertPathToDriveLetter('\\Device\\HarddiskVolume2\\Windows\\System32\\oleaccrc.dll')

reader = MapsReader(8480)
maps = reader.getMaps()
print("Results:")
for m in maps:
    print(repr(m))

tracker = PageUsageTracker()
tracker.reset()