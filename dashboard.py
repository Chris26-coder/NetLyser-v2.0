from flask import Flask, jsonify, send_from_directory
import os
import json

app = Flask(__name__)

STATUS_PATH = os.path.join(os.path.dirname(__file__), 'application_data', 'status.json')
REPORTS_DIR = os.path.join(os.path.dirname(__file__), 'application_data', 'attack_analysis')

@app.route('/')
def index():
    html = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Netlyser Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 20px; color: #222; }
    h1 { font-size: 20px; margin: 0 0 12px; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 12px; margin-bottom: 12px; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(240px, 1fr)); gap: 12px; }
    .label { color: #555; }
    .value { font-weight: 600; }
    #map { height: 360px; width: 100%; margin-top: 12px; border: 1px solid #ddd; border-radius: 8px; }
    .footer { color: #666; font-size: 12px; margin-top: 16px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  </style>
  <!-- Leaflet CSS -->
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="" />
</head>
<body>
  <h1>Netlyser Dashboard</h1>

  <div class="card">
    <div class="grid">
      <div><span class="label">IP Address:</span> <span id="ip" class="value mono">-</span></div>
      <div><span class="label">CPU:</span> <span id="cpu" class="value">-</span></div>
      <div><span class="label">MB/s:</span> <span id="mbps" class="value">-</span></div>
      <div><span class="label">Packets/s:</span> <span id="pps" class="value">-</span></div>
    </div>
  </div>

  <div class="card">
    <div class="grid">
      <div><span class="label">City:</span> <span id="city" class="value">-</span></div>
      <div><span class="label">Region:</span> <span id="region" class="value">-</span></div>
      <div><span class="label">Country:</span> <span id="country" class="value">-</span></div>
      <div><span class="label">Latitude:</span> <span id="latitude" class="value mono">-</span></div>
      <div><span class="label">Longitude:</span> <span id="longitude" class="value mono">-</span></div>
    </div>

    <div id="map"></div>
  </div>

  <div class="footer">Status updates every 3 seconds.</div>

  <!-- Leaflet JS -->
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
  <script>
    let map = null;
    let marker = null;
    let hasCentered = false;

    function initMap() {
      map = L.map('map');
      const defaultCenter = [20, 0]; // world view
      map.setView(defaultCenter, 2);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        errorTileUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAQAAABr9FQfAAAAGUlEQVR4nO3BMQEAAAgEIP9bB0wwQwAAAAAAAAAAAAAAwD0cB+YAAeKdbT0AAAAASUVORK5CYII='
      }).addTo(map);
    }

    async function fetchStatus() {
      try {
        const r = await fetch('/status');
        const j = await r.json();
        const s = j.status || {};
        const g = s.geo || {};

        document.getElementById('ip').textContent = s.ip || s.ip_address || '-';
        document.getElementById('cpu').textContent = s.cpu || '-';
        document.getElementById('mbps').textContent = (s.mbps ?? s.mb_per_sec ?? '-');
        document.getElementById('pps').textContent = (s.pps ?? s.packets_per_second ?? '-');

        document.getElementById('city').textContent = g.city || '-';
        document.getElementById('region').textContent = g.region || '-';
        document.getElementById('country').textContent = g.country || '-';
        document.getElementById('latitude').textContent = (typeof g.latitude === 'number') ? g.latitude.toFixed(6) : '-';
        document.getElementById('longitude').textContent = (typeof g.longitude === 'number') ? g.longitude.toFixed(6) : '-';

        // Update map and marker when we have valid coordinates
        if (typeof g.latitude === 'number' && typeof g.longitude === 'number') {
          const pos = [g.latitude, g.longitude];
          if (!marker) {
            marker = L.marker(pos).addTo(map);
            const labelIp = s.ip_address || 'IP';
            const labelCity = g.city || '';
            const labelRegion = g.region || '';
            const labelCountry = g.country || '';
            marker.bindPopup(`${labelIp} — ${labelCity} ${labelRegion} ${labelCountry}`.trim());
          } else {
            marker.setLatLng(pos);
          }
          // Center on location only on first valid update, keep user zoom/pan afterward
          if (!hasCentered) {
            const targetZoom = Math.max(map.getZoom(), 6);
            map.setView(pos, targetZoom);
            hasCentered = true;
          }
        } else {
          // Reset to world view if no coordinates
          map.setView([20, 0], 2);
          hasCentered = false;
          if (marker) {
            marker.remove();
            marker = null;
          }
        }
      } catch (e) {
        console.error('Failed to fetch status', e);
      }
    }

    // Initialize map and start polling
    initMap();
    fetchStatus();
    setInterval(fetchStatus, 3000);
  </script>
</body>
</html>
    '''
    return html

@app.route('/status')
def status():
    try:
        with open(STATUS_PATH, 'r', encoding='utf-8') as f:
            status = json.load(f)
    except Exception:
        status = {}
    return jsonify({ 'status': status })

@app.route('/report')
def report():
    # Serve files from the attack analysis directory (still available)
    return send_from_directory(REPORTS_DIR, 'index.html')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
