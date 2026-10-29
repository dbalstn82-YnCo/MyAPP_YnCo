"""exe 내장 서버 모드 검증: WebView2 원격 디버깅으로 대시보드·인프라 감시·자원 관리·네이티브 API 병합 확인"""
import base64, json, os, subprocess, sys, time, urllib.request
from pathlib import Path
import websocket
ENGINE = Path(r"C:\Users\dbals\Desktop\로그수집기\engine")
EXE = ENGINE / "deploy/local/dist/LogTriage.exe"
OUT = Path(__file__).parent / "shots_exe"; OUT.mkdir(exist_ok=True)
PORT = 9338
env = dict(os.environ); env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = f"--remote-debugging-port={PORT}"
subprocess.run("taskkill /F /IM LogTriage.exe", shell=True, capture_output=True); time.sleep(1)
proc = subprocess.Popen([str(EXE)], env=env, cwd=str(EXE.parent))
page = None
for _ in range(40):
    try:
        tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json"))
        page = next((t for t in tabs if t.get("type") == "page"), None)
        if page: break
    except Exception:
        pass
    time.sleep(1)
assert page, "webview page not found"
ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=120, suppress_origin=True)
mid = [0]
def call(m, p=None):
    mid[0] += 1; ws.send(json.dumps({"id": mid[0], "method": m, "params": p or {}}))
    while True:
        r = json.loads(ws.recv())
        if r.get("id") == mid[0]: return r.get("result", {})
def ev(x, aw=False):
    r = call("Runtime.evaluate", {"expression": x, "returnByValue": True, "awaitPromise": aw})
    if r.get("exceptionDetails"): return "JS_EXC:" + str(r["exceptionDetails"].get("exception", {}).get("description", ""))[:300]
    return r.get("result", {}).get("value")
def shot(n): (OUT / f"{n}.png").write_bytes(base64.b64decode(call("Page.captureScreenshot", {"format": "png"})["data"])); print("shot", n)
call("Page.enable"); call("Runtime.enable")
time.sleep(4)
R = {}
R["url"] = ev("location.href"); R["flags"] = ev("[!!window.LT_SERVER, !!window.LT_NATIVE, !!window.LT_API, !!(window.pywebview&&window.pywebview.api&&typeof window.pywebview.api.pick_logs==='function')]")
R["meta"] = ev("API().then(a=>a.meta()).then(m=>[m.rule_count,m.code_count])", True)
R["native_merge"] = ev("API().then(a=>[typeof a.pick_logs, typeof a.analyze, a.pick_logs.toString().includes('nat')])", True)
R["srv_links"] = ev("[...document.querySelectorAll('.nav a.srv')].map(a=>a.hidden)")
time.sleep(2); shot("40_exe_dashboard")
ev("location.href='/nms'"); time.sleep(3)
R["nms_title"] = ev("document.title")
ev("""fetch('/api/nms/save',{method:'POST',headers:{'Content-Type':'application/json','X-NMS-Request':'1'},body:JSON.stringify({name:'내 PC 웹서버',address:'127.0.0.1',kind:'server',method:'tcp',port:location.port*1,interval:10,timeout:2,fail_limit:3,recover_limit:2})}).then(r=>r.json())""", True)
time.sleep(6); ev("location.reload()"); time.sleep(3)
R["nms_status"] = ev("fetch('/api/nms/status').then(r=>r.json()).then(d=>d.targets.map(t=>[t.name,t.status]))", True)
shot("41_exe_nms")
ev("location.href='/resources'"); time.sleep(3); R["inv_title"] = ev("document.title"); shot("42_exe_resources")
# 자원 문서 편집(exe 내장 서버): 업로드 → 셀 수정 → 보기 화면 편집 도구 막대 → 삭제
sys.path.insert(0, str(ENGINE / "tests")); import test_inventory_docs as _tid
_raw = base64.b64encode(_tid.build(_tid.ROWS, _tid.MERGES)).decode()
_up = ev("""(async()=>{const b=Uint8Array.from(atob('%s'),c=>c.charCodeAt(0)); const r=await fetch('/api/inventory/docs?name=exe-test.xlsx',{method:'POST',headers:{'X-NMS-Request':'1'},body:b}); return r.json()})()""" % _raw, True)
R["doc_up"] = [_up.get("id"), _up.get("rows")]
R["doc_edit"] = ev("""fetch('/api/inventory/doc/edit',{method:'POST',headers:{'Content-Type':'application/json','X-NMS-Request':'1'},body:JSON.stringify({id:%s,sheet:'장비',rev:0,ops:[{op:'set',r:2,c:2,v:'exe기관'}]})}).then(r=>r.json()).then(d=>[d.rev,d.sheet.rows[2][1][1],d.sheet.rows[3][1][1]])""" % _up.get("id"), True)
ev("location.href='/resources/view?id=%s'" % _up.get("id")); time.sleep(3)
ev("document.getElementById('edit').click()"); time.sleep(0.6); R["doc_view_etb"] = ev("[!document.getElementById('etb').hidden, document.querySelectorAll('#xh tr.colrow th').length, [...document.querySelectorAll('#xb td[rowspan]')].map(t=>t.textContent)]"); shot("43_exe_doc_edit")
ev("fetch('/api/inventory/doc/delete',{method:'POST',headers:{'Content-Type':'application/json','X-NMS-Request':'1'},body:JSON.stringify({id:%s})}).then(r=>r.json())" % _up.get("id"), True)
ev("location.href='/'"); time.sleep(4)
ids = ev("fetch('/api/nms/status').then(r=>r.json()).then(d=>d.targets.map(t=>t.id))", True)
for i in ids or []:
    ev("fetch('/api/nms/delete',{method:'POST',headers:{'Content-Type':'application/json','X-NMS-Request':'1'},body:JSON.stringify({id:'%s'})}).then(r=>r.json())" % i, True)
R["hist"] = ev("API().then(a=>a.history()).then(h=>h.length)", True)
print(json.dumps(R, ensure_ascii=False))
ws.close(); subprocess.run("taskkill /F /IM LogTriage.exe", shell=True, capture_output=True)
