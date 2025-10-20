# Temporary runner to exercise netlyser startup and one monitoring iteration
import time
import json
from pathlib import Path

# Import main functions/variables from netlyser (compat shim kept for netdeflect)
import netlyser

# Start update checker thread (non-blocking)
netlyser.start_update_checker()

# load notification template (optional, skip if missing)
try:
    template_path = Path(__file__).resolve().parent / 'notification_template.json'
    if template_path.exists():
        with open(template_path, 'r', encoding='utf-8') as f:
            notif = json.load(f)
    else:
        notif = None
except Exception:
    notif = None

# Run a single network stats read and display
try:
    pps, mbps, cpu = netlyser.get_network_stats()
    netlyser.display_network_stats(pps, mbps, cpu)
    print('\nRan one monitoring iteration successfully')
except Exception as e:
    print('Error during single iteration:', e)

# exit
print('Runner finished')
