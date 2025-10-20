# NetLyser Local Dashboard

This repository includes a simple Flask dashboard to display NetLyser runtime metrics.

Files
- `dashboard.py` - Flask app that serves a status page at http://127.0.0.1:5000 and a `/status` JSON endpoint.
- `requirements.txt` - Install with `pip install -r requirements.txt`.
- `application_data/status.json` - Written by `netlyser.py` and consumed by the dashboard.
-- `netlyser.service` - Example systemd unit (install on Linux at `/etc/systemd/system/netlyser.service`).
- `install-windows-task.ps1` - PowerShell script to create a scheduled task on Windows to run `netlyser.py` at system startup.

Usage
1. Start NetLyser (or run `run_one_cycle.py` once) so `application_data/status.json` is present and updated.
2. Install Flask and run the dashboard:

```powershell
C:/Users/chris/AppData/Local/Programs/Python/Python313/python.exe -m pip install -r requirements.txt
C:/Users/chris/AppData/Local/Programs/Python/Python313/python.exe -u dashboard.py
```

3. Open http://127.0.0.1:5000 in your browser.

Production

- Create a Python virtualenv and install gunicorn in it.
- Use the provided `netdeflect-gunicorn.service` as an example systemd unit. Adjust paths and user/group accordingly.
- Use the provided `netdeflect-gunicorn.service` as an example systemd unit. Adjust paths and user/group accordingly. Note: `netdeflect.py` is kept as a compatibility shim that imports from `netlyser`.
- You can enable basic auth for the dashboard by setting environment variables:
	- `NETLYSER_DASH_USER` and `NETLYSER_DASH_PASS` — the dashboard will require HTTP Basic auth if these are set.

Security
- The bundled Flask server is for local debugging only. Use a production WSGI server (gunicorn, uWSGI) and a reverse proxy for public exposure.
- The `install-windows-task.ps1` creates a scheduled task as SYSTEM - adjust privileges per your environment.
