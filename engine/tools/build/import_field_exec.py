"""현장 보고 들여오기(8차 아이디어 ⑥) — 사이트·본사가 모은 '읽기 전용 1차 명령 실행 결과 보고'(성공·오류·오류 코드, 사이트 DB 면 머리글 이름)를
엔진의 검증 기록(errorcodes/_verification.yaml 의 field_exec)으로 옮긴다. 상용 DB 처럼 시험 환경이 없는 판정의 '실행' 축에 현장 보고를 붙인다.

  · 읽는 곳: 사이트 설치본 data/logtriage.db 의 exec_reports(사람·건·판정·명령마다 마지막 줄) 또는 본사 허브 DB 의 xrep(사이트별 묶음).
  · 멱등(GPT 64차 P0): 출처마다 **통째 교체**한다. 출처 = 사이트 ID(사이트 DB 옆 conf/hub.json 또는 --site, 허브는 줄마다 site_id).
    같은 DB 를 다시 넣어도·보고가 늘어난 DB 를 다시 넣어도·사이트 DB 와 허브를 둘 다 넣어도 두 번 세지 않는다.
  · 출처를 모르면(GPT 65차) 합산하지 않는다 — '출처 확인 필요'(field_exec_unconfirmed)로 따로 두고 보고서에만 적는다. --site <ID> 로 사이트를 정하면 합산.
  · 화면: 시험 PG 결과가 없으면 '현장 보고 성공 N(오류 M)'. 사람이 남긴 보고이지 앱이 실행을 확인한 것이 아니고, 진단이 맞았다는 뜻도 아니다.
  · 머리글은 미검증 칼럼 주장(Tibero V$LOCK 칼럼 등)을 사람이 대조하라고 보고서(지식검증/현장실행.md)에만 적는다(허브는 머리글을 받지 않는다).
사용: python tools/build/import_field_exec.py --db <logtriage.db | hub.sqlite3> [--db …]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

import yaml

ENGINE = Path(__file__).resolve().parents[2]
VP = ENGINE / "errorcodes" / "_verification.yaml"
OUT = ENGINE / "deploy" / "local" / "지식검증" / "현장실행.md"


def _blank() -> dict:
    return {"ok": 0, "error": 0, "codes": {}, "headers": {}}


def _site_of(db: Path) -> str:
    """사이트 DB(…/data/logtriage.db) 옆 conf/hub.json 의 site_id."""
    try:
        return str(json.loads((db.resolve().parent.parent / "conf" / "hub.json").read_text(encoding="utf-8")).get("site_id") or "")
    except (OSError, ValueError):
        return ""


def read_db(p: Path, site: str = "") -> dict:
    """{출처: {판정 키: {ok, error, codes, headers}}}"""
    out: dict = {}
    con = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)   # 읽기 전용으로 연다
    con.row_factory = sqlite3.Row
    try:
        tabs = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "exec_reports" in tabs:
            first = con.execute("SELECT at, vkey, cmd_hash FROM exec_reports ORDER BY id LIMIT 1").fetchone()
            if not first:
                return out
            sid = site or _site_of(p)
            src = f"site:{sid}" if sid else "unconfirmed:" + hashlib.sha256(f"{first['at']}|{first['vkey']}|{first['cmd_hash']}".encode()).hexdigest()[:16]
            per = out.setdefault(src, {})
            for r in con.execute("SELECT vkey, status, error_code, headers FROM exec_reports WHERE id IN "
                                 "(SELECT MAX(id) FROM exec_reports GROUP BY actor, incident_id, vkey, cmd_hash)").fetchall():
                d = per.setdefault(r["vkey"], _blank())
                d["ok" if r["status"] == "ok" else "error"] += 1
                if r["error_code"]:
                    d["codes"][r["error_code"]] = d["codes"].get(r["error_code"], 0) + 1
                if r["headers"]:
                    d["headers"][r["headers"]] = d["headers"].get(r["headers"], 0) + 1
        elif "xrep" in tabs:
            for r in con.execute("SELECT site_id, vkey, ok, error, codes FROM xrep").fetchall():
                d = out.setdefault(f"site:{r['site_id']}", {}).setdefault(r["vkey"], _blank())
                d["ok"] += int(r["ok"] or 0)
                d["error"] += int(r["error"] or 0)
                for c, n in (json.loads(r["codes"] or "{}") or {}).items():
                    d["codes"][c] = d["codes"].get(c, 0) + int(n)
        else:
            raise SystemExit(f"{p}: exec_reports·xrep 표가 없습니다(사이트 설치본 data/logtriage.db 또는 본사 허브 DB)")
    finally:
        con.close()
    return out


def total(sources: dict) -> dict:
    fe: dict = {}
    for per in sources.values():
        for k, v in per.items():
            cur = fe.setdefault(str(k).upper(), {"ok": 0, "error": 0, "sources": 0, "codes": {}, "headers": {}})
            cur["ok"] += int(v.get("ok", 0))
            cur["error"] += int(v.get("error", 0))
            cur["sources"] += 1
            for c, n in (v.get("codes") or {}).items():
                cur["codes"][c] = cur["codes"].get(c, 0) + int(n)
            for h, n in (v.get("headers") or {}).items():
                cur["headers"][h] = cur["headers"].get(h, 0) + int(n)
    for v in fe.values():
        v["codes"] = dict(sorted(v["codes"].items(), key=lambda kv: -kv[1])[:5])
        v["headers"] = [h for h, _ in sorted(v["headers"].items(), key=lambda kv: -kv[1])[:3]]
    return dict(sorted(fe.items()))


COLNAME = re.compile(r"(?<![\w$#])([A-Z][A-Z0-9_$#]{1,40})(?![\w$#])")


def column_check(fe: dict) -> dict:
    """9차 ⑤: 미확인 문구(verify_note)에 나온 대문자 칼럼 이름이 그 판정의 현장 머리글에 나왔는지. {판정: {seen, missing}}."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from make_vendor_requests import collect
    from vendor_doc_match import claim_key
    claimed: dict = {}
    for x in collect():
        names = {m for m in COLNAME.findall(x["claim"]) if "_" in m or len(m) <= 12}
        if names:
            claimed.setdefault(claim_key(x), set()).update(names)
    out = {}
    for k, v in fe.items():
        heads = {h.upper() for line in v.get("headers") or [] for h in str(line).split()}
        want = claimed.get(k.upper())
        if not heads or not want:
            continue
        seen = sorted(want & heads)
        if seen:
            out[k] = {"seen": seen, "missing": sorted(want - heads)[:12]}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", action="append", required=True)
    ap.add_argument("--site", default="", help="hub.json 이 없는 사이트 DB 의 사이트 ID(정하면 합산, 안 정하면 '출처 확인 필요')")
    a = ap.parse_args(argv)
    txt = VP.read_text(encoding="utf-8")
    head = "".join(l + "\n" for l in txt.splitlines() if l.startswith("#"))
    doc = yaml.safe_load(txt) or {}
    srcs = doc.get("field_exec_sources")
    srcs = dict(srcs) if isinstance(srcs, dict) else {}
    for d in a.db:
        got = read_db(Path(d), a.site.strip())
        for s, per in got.items():
            srcs[s] = per          # 출처마다 통째 교체 — 다시 넣어도 두 번 세지 않는다
            print(f"{Path(d).name}: 출처 {s} · 판정 {len(per)}개(교체)")
    conf = {k: v for k, v in srcs.items() if not k.startswith("unconfirmed:")}
    unc = {k: v for k, v in srcs.items() if k.startswith("unconfirmed:")}
    fe = total(conf)
    doc["field_exec_sources"] = srcs
    doc["field_exec"] = fe
    doc["field_exec_unconfirmed"] = sorted(unc)
    cols = column_check(fe)
    doc["field_columns"] = cols
    VP.write_text(head + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    md = ["# 현장 보고(읽기 전용 1차 명령 실행 결과)\n", f"들여온 시각 {time.strftime('%Y-%m-%d %H:%M')} · 판정 {len(fe)}개 · 합산한 출처 {len(conf)}곳"
          + (f" · **출처 확인 필요 {len(unc)}곳(합산 안 함 — --site 로 사이트를 정하십시오): {', '.join(sorted(unc))}**" if unc else ""),
          "사람이 남긴 보고입니다 — 앱이 실행을 확인한 것이 아니고 진단이 맞았다는 뜻도 아닙니다. 머리글은 미검증 칼럼 주장과 사람이 대조하십시오.\n",
          "| 판정 | 성공 | 오류 | 출처 | 오류 코드 | 머리글(칼럼 이름 · 사이트 DB 만) |", "|---|---|---|---|---|---|"]
    md += [f"| `{k}` | {v['ok']} | {v['error']} | {v['sources']} | {' '.join(f'{c}×{n}' for c, n in v['codes'].items())} | {' / '.join(v['headers'])} |"
           for k, v in sorted(fe.items(), key=lambda kv: -(kv[1]['ok'] + kv[1]['error']))]
    if cols:
        md += ["\n## 미검증 칼럼 주장 ↔ 현장 머리글(9차 ⑤)\n",
               "미확인 문구에 나온 칼럼 이름이 현장 출력 머리글에 **있다**는 것까지만 — 칼럼의 의미(보유/요청 등)는 확인하지 않습니다. "
               "없다고 나온 것은 다른 명령의 출력이거나 판이 다를 수 있습니다(틀렸다는 뜻 아님).\n",
               "| 판정 | 현장 머리글에 있음 | 현장 머리글에 없음 |", "|---|---|---|"]
        md += [f"| `{k}` | {', '.join(v['seen'])} | {', '.join(v['missing'])} |" for k, v in sorted(cols.items())]
    OUT.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"field_exec {len(fe)}개(합산 출처 {len(conf)}곳 · 출처 확인 필요 {len(unc)}곳) → {VP} · 보고서 {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
