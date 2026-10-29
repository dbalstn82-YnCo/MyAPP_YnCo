"""한 화면 캡처: python shot_one.py <url> <이름> [대기초=3] [js]  → shots_ux/<이름>.png"""
import base64, json, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path
import websocket
OUT = Path(__file__).parent / "shots_ux"; OUT.mkdir(exist_ok=True)
url, name = sys.argv[1], sys.argv[2]; wait = float(sys.argv[3]) if len(sys.argv) > 3 else 3; js = sys.argv[4] if len(sys.argv) > 4 else ""
PORT = 9345; EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
proc = subprocess.Popen([EDGE, "--headless=new", f"--remote-debugging-port={PORT}", "--window-size=1500,950", "--hide-scrollbars",
                         f"--user-data-dir={tempfile.mkdtemp(prefix='lt_edge_')}", "--no-first-run", "--disable-gpu", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(40):
    try:
        tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json")); break
    except Exception:
        time.sleep(0.5)
page = next(t for t in tabs if t.get("type") == "page")
ws_ = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=60, suppress_origin=True); mid = [0]
def call(m, p=None):
    mid[0] += 1; ws_.send(json.dumps({"id": mid[0], "method": m, "params": p or {}}))
    while True:
        r = json.loads(ws_.recv())
        if r.get("id") == mid[0]: return r.get("result", {})
call("Page.enable"); call("Runtime.enable"); call("Emulation.setDeviceMetricsOverride", {"width": 1500, "height": 950, "deviceScaleFactor": 1, "mobile": False})
call("Page.navigate", {"url": url}); time.sleep(wait)
if js:
    r = call("Runtime.evaluate", {"expression": js, "returnByValue": True, "awaitPromise": True}); print(json.dumps(r.get("result", {}).get("value"), ensure_ascii=False)); time.sleep(0.8)
(OUT / f"{name}.png").write_bytes(base64.b64decode(call("Page.captureScreenshot", {"format": "png"})["data"])); print("shot", name)
ws_.close(); proc.terminate()
