# Netlyser Quickstart

A lightweight DDoS monitoring and mitigation toolkit with a local web dashboard. It tracks live network metrics (CPU, MB/s, PPS), performs optional mitigation, and presents geo-location on a world map for your current IP.

---

# 🖥️ NetLyser Local Dashboard

NetLyser Local Dashboard is a lightweight Flask-based web interface designed to visualize runtime metrics collected by the NetLyser network analysis tool. It provides both a human-readable status page and a machine-consumable JSON endpoint, making it suitable for local monitoring, integration with other tools, or embedding in broader network observability platforms.

---

## 📁 Repository Structure and File Overview

| File/Folder | Description |
|------------|-------------|
| `dashboard.py` | Main Flask application that serves the dashboard UI and a `/status` JSON API. |
| `requirements.txt` | Python dependencies required to run the dashboard. Install with `pip install -r requirements.txt`. |
| `application_data/status.json` | JSON file written by `netlyser.py` containing current network metrics. This is the primary data source for the dashboard. |
| `netlyser.service` | Example systemd unit file for running NetLyser as a background service on Linux. Should be placed in `/etc/systemd/system/`. |
| `install-windows-task.ps1` | PowerShell script to register a scheduled task on Windows that runs `netlyser.py` at system startup. |
| `run_one_cycle.py` | Optional script to manually trigger a single NetLyser data collection cycle, useful for testing or debugging. |

---

## 🚀 Getting Started

### Step 1: Generate Runtime Metrics

Before launching the dashboard, ensure that NetLyser has generated the `status.json` file:

- Run NetLyser manually:
  ```bash
  python netlyser.py
  ```
- Or trigger a one-time data collection:
  ```bash
  python run_one_cycle.py
  ```

This will populate `application_data/status.json` with metrics such as latency, packet loss, DNS resolution times, and other diagnostic data.

---

### Step 2: Install Dependencies and Launch Dashboard

Use the following commands to install dependencies and start the Flask server:

```powershell
C:/Users/chris/AppData/Local/Programs/Python/Python313/python.exe -m pip install -r requirements.txt
C:/Users/chris/AppData/Local/Programs/Python/Python313/python.exe -u dashboard.py
```

Once running, open your browser and navigate to:

```
http://127.0.0.1:5000
```

You’ll see a simple HTML dashboard displaying the latest metrics. For programmatic access, use:

```
http://127.0.0.1:5000/status
```

This endpoint returns the raw JSON data from `status.json`.

---

## 🏭 Production Deployment

For production environments, it's recommended to use a robust WSGI server and service manager:

### Using Gunicorn with systemd (Linux)

1. Create a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install gunicorn
   ```

2. Use the provided `netdeflect-gunicorn.service` as a template:
   - Update paths to match your environment.
   - Set the correct user/group.
   - Ensure the working directory points to the dashboard folder.

3. Enable and start the service:
   ```bash
   sudo systemctl enable netdeflect-gunicorn.service
   sudo systemctl start netdeflect-gunicorn.service
   ```

> Note: `netdeflect.py` is a compatibility wrapper that imports and runs NetLyser logic. It ensures backward compatibility with older deployments.

---

## 🔐 Authentication and Security

### Basic Authentication

To restrict access to the dashboard, set the following environment variables before launching the app:

```bash
export NETLYSER_DASH_USER=admin
export NETLYSER_DASH_PASS=securepassword
```

This enables HTTP Basic Auth on both the HTML dashboard and the `/status` endpoint.

### Security Best Practices

- The built-in Flask server is intended for local development only. For public or remote access:
  - Use Gunicorn or uWSGI behind a reverse proxy (e.g., Nginx).
  - Enable HTTPS using a valid TLS certificate.
  - Restrict access via firewall or VPN.
- On Windows, the PowerShell script creates a scheduled task that runs as SYSTEM. Consider adjusting the privileges to a less privileged user if needed.

---

## 🧪 Testing and Debugging

- Use `run_one_cycle.py` to simulate a NetLyser run and populate `status.json`.
- Modify `dashboard.py` to add logging or custom metrics.
- Validate JSON output at `/status` using tools like `curl` or Postman.

---

## 📌 Notes

- The dashboard is designed to be minimal and fast. For richer visualizations, consider integrating with tools like Grafana or Prometheus.
- You can extend `dashboard.py` to include charts (e.g., using Chart.js or Plotly), historical data, or alerting logic.

---

