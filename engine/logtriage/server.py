"""LogTriage 서버형(Linux) — 브라우저로 접속하는 웹 UI + JSON API.

설계 원칙
  · 데스크톱(pywebview)과 같은 ui.html·같은 Api 를 그대로 재사용한다. 브라우저에는 작은 JS 심(SHIM)을 주입해
    window.pywebview.api 호출을 HTTP(/api/<메서드>)로 바꾼다 → 화면·기능이 exe 와 100% 동일.
  · 표준 라이브러리(http.server)만 사용 — 인터넷이 없는 설치 환경에서도 PyYAML 외 추가 의존성 없음.
  · 파일은 브라우저에서 업로드(PUT /api/upload, 스트리밍 저장, 1파일 600MB 상한)하거나
    서버 로컬 경로(--allow-dir 로 허용한 디렉터리)를 직접 지정할 수 있다.
  · 접속 보호: --password(또는 환경변수 LOGTRIAGE_PASSWORD)가 있으면 로그인 후 쿠키 세션. TLS 는 앞단(nginx/httpd)에서.
  · 동시 사용: 스레드 서버. 분석 이력·이벤트 원본은 DB(storage.py: SQLite 기본 / PostgreSQL 선택)에 저장.
  · 구성(오픈소스 스택): nginx(WEB, TLS·업로드 상한) → 이 프로세스(WAS, systemd) → SQLite 또는 PostgreSQL(DBMS).
  · 서버형 전용 메뉴(2026-09-11 병합, Codex preview2 기반): /nms 인프라 감시(등록한 IP 의 ICMP·TCP 가용성 수집·장애/복구 이력),
    /resources 자산 관리(자원정보.xlsx 6개 시트 양식 업로드·검색·편집). 분석 DB 와 분리된 SQLite(data/nms, data/inventory)에 저장.

실행:  python -m logtriage.server --host 127.0.0.1 --port 8088 --base /opt/logtriage [--password ...] [--allow-dir /var/log]
       [--db sqlite:////opt/logtriage/data/logtriage.db | postgresql://logtriage:pw@127.0.0.1:5432/logtriage]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import threading
import time
import urllib.parse
import zipfile
import io
from datetime import datetime
from html import escape as html_escape
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import BUILD, __version__, rulepack
from . import auth as authmod
from . import privacy
from .board import Board, BoardError
from . import buildid
from . import runlock
from . import hub as hubmod
from .detect import detect_product
from .gui.app import Api, ui_path
from .inventory import inspect as inspect_workbook
from .inventory_docs import DocStore, EditConflict
from .nms import OID_RE
from .nms import Collector as NmsCollector, Store as NmsStore
from .resource_inventory import ResourceInventory
from . import asset_spec as asset_spec_mod
from . import asset_custom as asset_custom_mod
from . import storage
from .storage import Storage, sqlite_url

MAX_UPLOAD = 600 * 1024 * 1024  # 사용법 문서의 1회 처리 한도와 동일
MAX_ACTIVE = int(os.environ.get("LOGTRIAGE_MAX_ACTIVE", "3"))  # 동시 분석+업로드 상한(초과 시 즉시 거절)
_ACTIVE = threading.BoundedSemaphore(MAX_ACTIVE)
API_NAMES = ("meta", "default_time", "detect", "analyze", "analyze_progress", "history", "rules_list", "search_kb",
             "stats", "log_incidents", "search_logs", "generate_report", "list_dir", "kb_overview", "kb_product", "pack_info", "similar_cases", "preview_rule", "add_local_rule", "delete_local_rule", "report_profile", "save_report_profile", "report_profile_sources", "report_profile_get", "diag", "set_report_dir",
             "custom_forms", "custom_form_analyze", "custom_form_save", "custom_form_delete", "custom_form_preview", "custom_form_pin", "custom_form_ledger", "custom_form_ledger_check",
             "report_style_info", "learn_report_style",
             "demo_status", "demo_seed", "demo_clear",   # 시연 자료(관리자만)
             "effect_report", "effect_set",             # 업무 절감 효과
             "pilot_metrics",                            # 22차: 시범 운영 지표(측정값만)
             "actions", "action_add", "set_status", "past_actions",   # 조치 기록(자산화)
             "home",                                    # 개인화 홈
             "asset_spec", "asset_check", "asset_map",   # 자산 기준 항목
             "asset_fields", "asset_field_add", "asset_field_rename",
             "asset_field_level", "asset_field_remove",   # 기준 손보기(관리자)
             "learn_list", "learn_suggest", "learn_check", "learn_rules",            # 룰 학습(2026-10-13)
             "learn_approve", "learn_dismiss", "learn_restore", "learn_remove_rule", "learn_build_pack",
             "quickfind",                               # Ctrl+K 찾기(GPT UI 19차)
             "kb_feedback", "kb_feedback_summary", "interpret_output",   # 1차 명령 현장 피드백·결과 해석(2026-10-16)
             "postmortem_get", "postmortem_set", "postmortem_review",    # 사후 원인 기록·판정 적중 검토
             "host_version_set", "version_reevaluate",                   # 7차: 호스트별 판 지정·확인과 재평가
             "kb_attention", "postmortem_proposals",                     # 7차: 확인이 필요한 지식 표·룰 개선 제안 초안
             "exec_report", "exec_report_summary", "version_signals",    # 8차: 현장 실행 결과(머리글만)·판 다름 신호 → 판 지정 제안
             "incident_group_set", "incident_groups_list",               # 8차: 사후 원인 장애 묶음 합치기·나누기(관리자)
             "install_check", "governance_report", "link_review_assist",  # 9차: 설치본 무결성 띠·결정 감사 월보·연결 승인 도우미
             "restore_legacy_history", "ack_history_change",             # 10차: 이관 파일 분석 가져오기·이력 감소 확인(관리자)
             "sample_logs",                                              # 10차: 견본 로그 넣기(합성 견본)
             "code_solution")                                            # 12차: 에러코드 × OS 해법(명령어 포함)

# Ctrl+K 찾기 빈도 상한 — 계정(없으면 접속 주소)마다 QF_WINDOW 초에 QF_MAX 번
QF_MAX, QF_WINDOW = 30, 10.0
_QF_HITS: dict[str, list[float]] = {}
_QF_LOCK = threading.Lock()


def _qf_allow(who: str) -> bool:
    now = time.monotonic()
    with _QF_LOCK:
        if len(_QF_HITS) > 5000:                      # 오래된 열쇠가 쌓이지 않게
            for k in [k for k, v in _QF_HITS.items() if not v or now - v[-1] > QF_WINDOW]:
                _QF_HITS.pop(k, None)
        hits = [t for t in _QF_HITS.get(who, []) if now - t < QF_WINDOW]
        if len(hits) >= QF_MAX:
            _QF_HITS[who] = hits
            return False
        hits.append(now)
        _QF_HITS[who] = hits
        return True


# 권한: 조회(viewer)는 읽기 API 만, 운영(operator)은 분석·등록·예약, 관리자(admin)는 사용자·사이트·룰팩·서버 경로 변경(r4)
READ_APIS = frozenset(("effect_report", "pilot_metrics", "meta", "default_time", "detect", "history", "rules_list", "search_kb", "stats", "log_incidents", "search_logs",
                       "kb_overview", "kb_product", "pack_info", "similar_cases", "preview_rule", "report_profile", "report_profile_sources", "report_profile_get", "diag",
                       "custom_forms", "custom_form_preview", "report_style_info", "custom_form_ledger_check",
                       "actions", "past_actions", "home", "quickfind",
                       "asset_spec", "asset_check", "asset_map", "asset_fields",
                       "kb_feedback_summary", "interpret_output", "postmortem_get", "version_reevaluate", "kb_attention",
                       "exec_report_summary", "version_signals", "install_check", "sample_logs", "code_solution"))   # 읽기는 보기 권한부터
# 기준을 바꾸는 일은 관리자만 — 필수를 내리는 한 번이 그 뒤 모든 사이트의 대장을 헐겁게 한다
ADMIN_APIS = frozenset(("set_report_dir", "demo_seed", "demo_clear", "demo_status", "effect_set", "restore_legacy_history", "ack_history_change",
                        "asset_field_add", "asset_field_rename", "asset_field_level",
                        "asset_field_remove",
                        # 룰 학습: 판정을 바꾸는 승인·삭제와 룰팩 서명은 관리자만(룰팩 = 관리자 — r4)
                        # 후보 틀에는 내부 이름이 남을 수 있고, 임의 정규식 검증도 부하가 된다 — 조회까지 관리자만(GPT P1-03)
                        "learn_list", "learn_suggest", "learn_check", "learn_rules",
                        "learn_approve", "learn_dismiss", "learn_restore", "learn_remove_rule", "learn_build_pack",
                        "postmortem_review", "postmortem_proposals",   # 판정 적중 검토·개선 제안 초안 — 룰을 바꿀 근거가 되는 목록(사람 검토 후에만 룰 수정)
                        "incident_group_set", "incident_groups_list",   # 8차 ⑩ 개선 제안의 '서로 다른 장애' 판단을 바꾸는 일
                        "governance_report", "link_review_assist"))       # 9차: 관리자 결정 감사·연결 승인 도우미
AUDIT_READ = frozenset(("search_logs",))   # 읽기지만 로그 원문을 보는 요청은 감사 기록
LEGACY_USER = {"login": "(공용)", "name": "공용 접속", "dept": "", "email": "", "role": "admin", "sites": ["*"], "source": "legacy"}

# 예약·자동화 메뉴: 공용 사이드바(nav.nav)의 '자산 관리' 항목을 복제해 그 아래에 추가한다 — 화면 우하단 고정 버튼은
# nms.html 의 알림 패널(#alarms, position:fixed;bottom:18px;right:16px)과 겹치므로 사용하지 않는다(r2).
NAV_JS = r"""(function(){var ST='.lt-me{margin:8px 12px 0;padding:10px 12px;border-radius:10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.08);color:var(--side-ink,#C9D6DF);font-size:12px;line-height:1.45}.lt-me b{display:block;color:var(--side-hi,#fff);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.lt-me small{display:block;opacity:.8}.lt-me a{display:inline-block;margin-top:6px;color:#7FD6E6;text-decoration:none;font-weight:600;cursor:pointer}.lt-me a:hover{text-decoration:underline}.lt-noasset #add,.lt-noasset [data-action=edit],.lt-noasset [data-action=delete]{display:none!important}@media(max-width:760px){.lt-me{display:none}}';function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}function run(){fetch('/api/me',{credentials:'same-origin'}).then(function(r){seen(r);return r.ok?r.json():null}).then(function(me){if(!me)return;window.LT_ME=me;try{var md=document.getElementById('lt-mode');if(md){md.querySelector('span').textContent=me.logout?'사내 서버 · '+(me.role_ko||''):'이 PC 전용';md.hidden=false}}catch(_){}if(!me.is_admin)document.querySelectorAll('nav.nav a[data-href="/admin"]').forEach(function(a){a.remove()});if(!me.can_operate)document.documentElement.classList.add('lt-viewer');if(!me.can_assets)document.querySelectorAll('nav.nav a[data-href="/resources"]').forEach(function(a){a.remove()});if(!me.can_assets)document.documentElement.classList.add('lt-noasset');var side=document.querySelector('.side');if(!side||document.getElementById('lt-me'))return;var st=window.ltStyleEl();st.textContent=ST;document.head.appendChild(st);var d=document.createElement('div');d.id='lt-me';d.className='lt-me';d.innerHTML='<b title="'+esc(me.login)+'">'+esc(me.name||me.login)+'</b><small>'+esc(me.role_ko)+(me.site?' · '+esc(me.site.name):'')+(me.dept?' · '+esc(me.dept):'')+'</small>'+(me.logout?'<a href="/logout">로그아웃</a>':'');var foot=side.querySelector('.foot');if(foot)side.insertBefore(d,foot);else side.appendChild(d);try{gnb()}catch(e){}}).catch(function(){})}function nav(){var n=document.querySelector('nav.nav');if(!n)return;n.querySelectorAll('a.on').forEach(function(a){a.setAttribute('aria-current','page')});var kids=[].slice.call(n.children),grp=null,seen=0;function close(){if(grp)grp.hidden=(seen===0)}kids.forEach(function(el){if(el.classList.contains('grp')){close();grp=el;seen=0;return}if(!el.hidden)seen++});close()}function link(){if(window.__ltLink)return;window.__ltLink=1;function tgt(e){return e.target&&e.target.closest?e.target.closest('a[data-href]'):null}function go(a,e){if(a.hasAttribute('href'))return;var h=a.getAttribute('data-href');if(!h||h==='#'||!(h=(window.LT_OKHREF||function(){return''})(h))||e.defaultPrevented||e.repeat)return;e.preventDefault();if(e.ctrlKey||e.metaKey||e.shiftKey||e.button===1||a.getAttribute('target')==='_blank'){window.open(h,'_blank','noopener');return}location.href=h}document.addEventListener('click',function(e){var a=tgt(e);if(a)go(a,e)});document.addEventListener('auxclick',function(e){var a=tgt(e);if(a&&e.button===1)go(a,e)});document.addEventListener('keydown',function(e){if(e.key!=='Enter')return;var a=tgt(e);if(a)go(a,e)});function tab(){document.querySelectorAll('a[data-href]:not([tabindex])').forEach(function(a){a.tabIndex=0;a.setAttribute('role','link')})}var qd=0;function queue(){if(qd)return;qd=1;(window.requestAnimationFrame||setTimeout)(function(){qd=0;tab()},16)}new MutationObserver(queue).observe(document.documentElement,{childList:true,subtree:true});tab()}var FST='.nav .grp{cursor:pointer;-webkit-user-select:none;user-select:none}.nav .grp::after{content:"";float:right;margin-top:5px;width:0;height:0;border-left:4px solid currentColor;border-top:3.5px solid transparent;border-bottom:3.5px solid transparent;transform:rotate(90deg);transition:transform .15s}.nav .grp.lt-folded::after{transform:rotate(0deg)}.nav .grp:hover{color:var(--side-hi,#fff)}.nav .grp:focus-visible{outline:2px solid var(--side-acc,#2BC5DB);outline-offset:2px;border-radius:6px}@media(min-width:761px){.nav .lt-hid{display:none!important}}@media(min-width:761px){.side{overflow:hidden}.side .logo,.side .lt-me,.side .foot{flex-shrink:0}.side .nav{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;scroll-padding-top:52px;scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.26) transparent;overscroll-behavior:contain}.side .nav .home{position:sticky;top:0;z-index:2;background:linear-gradient(rgba(45,212,206,.13),rgba(45,212,206,.13)),var(--side-bg,#14212B);box-shadow:0 6px 10px -8px rgba(0,0,0,.9)}.side .nav .home.on{background:var(--side-acc,#2DD4CE)}.side .nav::-webkit-scrollbar{width:8px}.side .nav::-webkit-scrollbar-track{background:transparent}.side .nav::-webkit-scrollbar-thumb{background:rgba(255,255,255,.20);border-radius:99px}.side .nav:hover::-webkit-scrollbar-thumb{background:rgba(255,255,255,.34)}}.nav button.grp{font-family:inherit;background:none;border:0;margin:0;width:100%;text-align:left;-webkit-appearance:none;appearance:none}.nav .home{background:rgba(45,212,206,.10);border:1px solid rgba(45,212,206,.32);color:var(--side-hi,#fff);font-weight:700;margin-bottom:2px}.nav .home:hover{background:rgba(45,212,206,.20)}.nav .home.on{background:var(--side-acc,#2DD4CE);color:#0A1014;border-color:transparent}.lt-tip{position:fixed;left:-9999px;top:0;z-index:9990;max-width:250px;padding:8px 11px;border-radius:9px;background:#0B141B;color:#DCE7EE;border:1px solid rgba(255,255,255,.16);box-shadow:0 10px 26px rgba(0,0,0,.5);font-size:12px;line-height:1.55;pointer-events:none;opacity:0;transition:opacity .12s}.lt-tip.lt-on{opacity:1}.lt-tip b{display:block;color:#fff;font-size:12.5px;margin-bottom:3px}.lt-tip i{display:block;margin-top:5px;font-style:normal;font-size:11.5px;opacity:.72}@media(max-width:760px){.lt-tip{display:none}}';function fold(){var n=document.querySelector('nav.nav');if(!n)return;try{if(!document.getElementById('lt-fold-css')){var st=window.ltStyleEl();st.id='lt-fold-css';st.textContent=FST;document.head.appendChild(st)}var gs=[],cur=null;[].slice.call(n.children).forEach(function(el){if(el.classList&&el.classList.contains('grp')){cur={h:el,it:[]};gs.push(cur);return}if(cur)cur.it.push(el)});var FOLD_SCHEMA='2';function key(g){return 'lt.fold.'+FOLD_SCHEMA+'.'+(g.h.getAttribute('data-grp')||(g.h.textContent||'').trim())}function rd(g){try{var v=localStorage.getItem(key(g));return v===null?true:v==='1'}catch(e){return true}}function wr(g,v){try{localStorage.setItem(key(g),v?'1':'0')}catch(e){}}function cur_(el){return !!((el.matches&&el.matches('.on'))||(el.querySelector&&el.querySelector('.on')))}function paint(g){g.h.setAttribute('aria-expanded',g.f?'false':'true');g.h.classList.toggle('lt-folded',!!g.f);g.it.forEach(function(el){if(el.classList)el.classList.toggle('lt-hid',!!g.f)})}n.__ltSync=function(){gs.forEach(function(g){var f=rd(g);if(f&&g.it.some(cur_))f=false;if(g.f!==f){g.f=f;paint(g)}})};gs.forEach(function(g){g.f=rd(g);if(g.f&&g.it.some(cur_))g.f=false;paint(g);if(g.h.dataset.ltFold)return;g.h.dataset.ltFold='1';var btn=g.h.tagName==='BUTTON';if(!btn){g.h.setAttribute('role','button');g.h.tabIndex=0}function t(){g.f=!g.f;wr(g,g.f);paint(g)}g.h.addEventListener('click',t);if(!btn)g.h.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();t()}})});try{if(!n.dataset.ltSeen){n.dataset.ltSeen='1';var onEl=n.querySelector('.on');if(onEl&&!onEl.classList.contains('lt-hid')&&window.matchMedia&&window.matchMedia('(min-width:761px)').matches){var hm=n.querySelector('.home'),er=onEl.getBoundingClientRect(),nr=n.getBoundingClientRect(),top=nr.top+(hm?hm.getBoundingClientRect().height:0);if(er.top<top)n.scrollTop-=(top-er.top);else if(er.bottom>nr.bottom)n.scrollTop+=(er.bottom-nr.bottom)}}}catch(e){}}catch(e){try{[].slice.call(n.querySelectorAll('.lt-hid')).forEach(function(el){el.classList.remove('lt-hid')});[].slice.call(n.querySelectorAll('.grp')).forEach(function(h){h.setAttribute('aria-expanded','true');h.classList.remove('lt-folded')})}catch(_){}if(window.console&&console.warn)console.warn('LogTriage: 사이드바 접기 실패 — 메뉴를 모두 펴 둡니다',e)}}var TIP={home:'로그인하면 먼저 뜨는 화면 — 확인 안 한 알림, 조치 중인 건, 내 최근 분석을 모아 봅니다.',all:'전사 분석 건수·심각도와 무인 1차 대응 현황을 한눈에 봅니다.',dash:'전사 분석 건수·심각도와 무인 1차 대응 현황을 한눈에 봅니다.',new:'로그 파일을 올려 장애 원인과 1차 조치를 분석합니다.',report:'분석 결과를 상황관리·사후관리 보고서로 만들어 내려받습니다.',logsearch:'모아 둔 로그에서 기간·호스트·낱말로 찾습니다.',hist:'지난 분석 건을 다시 열어 보고서를 다시 만듭니다.',rules:'장애 코드와 원인·조치 절차를 찾아봅니다.',forms:'보고서 양식(HWPX)을 등록하거나 바꿉니다.',pack:'탐지 규칙 묶음(룰팩)을 새 파일로 갱신합니다.',nms:'장비 가용성·자원 사용률을 지켜보고 임계값을 넘으면 알립니다.',inv:'자원 정보 문서를 올려 장비 대장을 만듭니다.',auto:'반입 폴더 감시·주기 실행과 무인 1차 대응을 설정합니다.',hub:'여러 사이트의 분석 현황을 본사에서 모아 봅니다.',board:'장애 사례와 질문을 함께 보는 게시판입니다.',admin:'사용자·권한과 시연 자료를 관리합니다.'};var GRP={analysis:'로그를 넣어 원인과 근거를 찾고 대응 결과를 남기는 곳',knowledge:'지난 분석과 장애 지식·보고서 기준을 찾아보는 곳',manage:'분석 규칙과 대상 자산, 자동 대응을 설정하는 곳',ops:'여러 사이트 현황을 보고 사용자·협업을 운영하는 곳'};var THREF={'/':'home','/#dash':'all','/#new':'new','/#report':'report','/#logsearch':'logsearch','/#hist':'hist','/#rules':'rules','/#forms':'forms','/#pack':'pack','/nms':'nms','/resources':'inv','/automation':'auto','/hub':'hub','/board':'board','/admin':'admin'};function ttxt(el){var t='';[].slice.call(el.childNodes||[]).forEach(function(n){if(n.nodeType===3)t+=n.nodeValue});t=t.replace(/\s+/g,' ').trim();return t||((el.textContent||'').replace(/\s+/g,' ')).trim()}function tkey(el){var ic=el.querySelector&&el.querySelector('[data-icon]');if(ic)return ic.getAttribute('data-icon')||'';return el.getAttribute('data-go')||THREF[el.getAttribute('data-href')||el.getAttribute('href')||'']||''}function tips(){var n=document.querySelector('nav.nav');if(!n)return;try{var box=document.getElementById('lt-tip');if(!box){box=document.createElement('div');box.id='lt-tip';box.className='lt-tip';box.setAttribute('role','tooltip');document.body.appendChild(box)}var head=null,list=[];function flush(){if(!head)return;head.setAttribute('data-tip',GRP[head.getAttribute('data-grp')||'']||'메뉴 묶음입니다');head.setAttribute('data-tip2','담긴 항목: '+(list.length?list.join(', '):'없음')+' · 눌러서 접기·펼치기')}[].slice.call(n.children).forEach(function(el){if(!el.classList)return;if(el.classList.contains('grp')){flush();head=el;list=[];return}var t=TIP[tkey(el)];if(t){el.setAttribute('data-tip',t);if(el.removeAttribute)el.removeAttribute('title')}if(head&&!el.hidden)list.push(ttxt(el))});flush();if(n.dataset.ltTip)return;var tm=0,cur=null,wired=[];function hide(){clearTimeout(tm);if(cur&&cur.removeAttribute)cur.removeAttribute('aria-describedby');cur=null;box.classList.remove('lt-on')}function show(el){var t=el.getAttribute('data-tip');if(!t)return;if(el.isConnected===false||!n.contains(el)){hide();return}cur=el;el.setAttribute('aria-describedby','lt-tip');var t2=el.getAttribute('data-tip2');box.innerHTML='<b>'+esc(ttxt(el))+'</b>'+esc(t)+(t2?'<i>'+esc(t2)+'</i>':'');box.style.left='-9999px';box.classList.add('lt-on');var r=el.getBoundingClientRect(),bw=box.offsetWidth,bh=box.offsetHeight,w=window.innerWidth,h=window.innerHeight;var x=r.right+10;if(x+bw>w-8)x=Math.max(8,r.left-bw-10);var y=Math.round(r.top+r.height/2-bh/2);if(y+bh>h-8)y=h-8-bh;if(y<8)y=8;box.style.left=x+'px';box.style.top=y+'px'}function at(e){return e.target&&e.target.closest?e.target.closest('nav.nav>*'):null}function on_(t,ev,fn,cap){t.addEventListener(ev,fn,cap);wired.push([t,ev,fn,cap])}try{on_(n,'mouseover',function(e){var el=at(e);if(!el){hide();return}if(el===cur)return;hide();cur=el;tm=setTimeout(function(){if(cur===el)show(el)},110)});on_(n,'mouseleave',hide);on_(n,'click',hide);on_(n,'focusin',function(e){var el=at(e);if(el)show(el)});on_(n,'focusout',hide);on_(n,'scroll',hide,{passive:true});on_(window,'scroll',hide,true);on_(window,'resize',hide);on_(window,'hashchange',hide);on_(window,'popstate',hide);on_(window,'pagehide',hide);on_(window,'keydown',function(e){if(e.key==='Escape')hide()});on_(document,'visibilitychange',function(){if(document.hidden)hide()});n.dataset.ltTip='1'}catch(e){wired.forEach(function(a){try{a[0].removeEventListener(a[1],a[2],a[3])}catch(_){}});throw e}}catch(e){if(window.console&&console.warn)console.warn('LogTriage: 메뉴 설명 말풍선 실패 — 메뉴는 그대로 씁니다',e)}}var GST=@@GNB_CSS@@,GBAR=@@GNB_BAR@@;var CAT={alarm:'장애',failed:'실패',job_failed:'작업 실패',tmp_backup:'임시 백업',recovery:'복구',recovered:'복구',down:'중단',report:'보고서',auto:'무인 1차 대응',info:'알림'};function ago(sec){var d=Date.now()/1000-(sec||0);if(d<60)return'방금';if(d<3600)return Math.floor(d/60)+'분 전';if(d<86400)return Math.floor(d/3600)+'시간 전';return Math.floor(d/86400)+'일 전'}var POP=null,POPOWN=null;function popClose(back){if(POP)POP.remove();POP=null;if(POPOWN){POPOWN.setAttribute('aria-expanded','false');if(back&&POPOWN.focus){try{POPOWN.focus()}catch(e){}}}POPOWN=null}function popOpen(btn,html){if(POPOWN===btn){popClose();return null}popClose();POP=document.createElement('div');POP.className='lt-pop';POP.innerHTML=html;document.body.appendChild(POP);POPOWN=btn;btn.setAttribute('aria-expanded','true');var r=btn.getBoundingClientRect(),w=POP.offsetWidth,x=Math.min(r.right-w,window.innerWidth-8-w);POP.style.left=Math.max(8,x)+'px';POP.style.top=(r.bottom+8)+'px';return POP}var MYB=function(){try{var m=document.querySelector('meta[name=lt-build]');return m?(m.content||''):''}catch(e){return''}}();function sweepSW(){try{if(navigator.serviceWorker&&navigator.serviceWorker.getRegistrations)navigator.serviceWorker.getRegistrations().then(function(rs){rs.forEach(function(r){try{r.unregister()}catch(e){}})}).catch(function(){})}catch(e){}}var SST='#lt-stale{position:fixed;left:0;right:0;bottom:0;z-index:9999;display:flex;align-items:center;gap:12px;padding:12px 16px;background:#8A2B16;color:#fff;font-size:13px;line-height:1.5;box-shadow:0 -4px 16px rgba(0,0,0,.45)}#lt-stale b{flex:0 0 auto;font-weight:700}#lt-stale span{flex:1 1 auto}#lt-stale button{flex:0 0 auto;font-family:inherit;font-size:13px;font-weight:700;padding:7px 14px;border-radius:8px;border:0;background:#fff;color:#8A2B16;cursor:pointer}#lt-stale button:hover{background:#FFE9E2}#lt-stale code{font-size:11.5px;opacity:.8}@media(max-width:760px){#lt-stale{flex-wrap:wrap;gap:8px}}';function staleBar(){if(document.getElementById('lt-stale'))return;try{if(!document.getElementById('lt-stale-css')){var st=window.ltStyleEl();st.id='lt-stale-css';st.textContent=SST;document.head.appendChild(st)}var d=document.createElement('div');d.id='lt-stale';d.setAttribute('role','alert');d.innerHTML='<b>서버가 새 판으로 바뀌었습니다</b><span>이 화면은 바뀌기 전의 옛 코드로 돌고 있습니다 — 작업 중인 내용을 저장한 뒤 새로 불러오십시오.</span><button type="button">새로 불러오기</button>';document.body.appendChild(d);d.querySelector('button').addEventListener('click',function(){location.reload()})}catch(e){if(window.console&&console.warn)console.warn('LogTriage: 서버 판이 바뀌었습니다 — 화면을 새로 불러오십시오',e)}}
/* 응답 머리글에 실려 오는 서버의 판 지문과 **이 화면을 만든 판**을 맞춰 본다. 새 요청을
   따로 내지 않는다 — 이미 60초마다 도는 알림 조회에 얹는다. 다르면 띠를 띄우되
   **스스로 새로 불러오지는 않는다**: 분석 도중인 입력을 말없이 날리는 쪽이 더 큰 사고다. */
function seen(r){try{var b=(r&&r.headers&&r.headers.get)?r.headers.get('X-LogTriage-Build'):'';if(MYB&&b&&b!==MYB)staleBar()}catch(e){}}
/* no-store 를 붙였어도 브라우저가 **실행 상태 그대로** 화면을 되살릴 수 있다(bfcache).
   캐시에서 응답을 다시 쓰는 것이 아니라 대본과 DOM 을 살려 두었다가 되돌리는 것이라,
   저장 금지로는 막히지 않는다 — 크롬이 2025년에 no-store 화면도 담도록 바꿨다.
   되살아난 그 순간에 한 번 더 맞춰 본다. 되돌린 내용을 버리지는 않는다(입력 보호). */
function revived(e){if(!e||!e.persisted)return;try{fetch('/healthz',{cache:'no-store',credentials:'same-origin'}).then(seen).catch(function(){})}catch(x){}}
var NOTE={unack:0,notices:[],ok:false,err:'',gone:false};function notePaint(){var b=document.getElementById('lt-bell');if(!b)return;if(NOTE.gone){b.hidden=true;return}b.hidden=false;var n=b.querySelector('.n');if(NOTE.err){n.hidden=true;b.classList.add('err');b.title='알림을 불러오지 못했습니다 — '+NOTE.err;return}b.classList.remove('err');n.textContent=NOTE.unack>99?'99+':NOTE.unack;n.hidden=!NOTE.unack;b.title=NOTE.unack?('안 읽은 알림 '+NOTE.unack+'건'):'알림'}function noteFetch(){return fetch('/api/automation/notices?limit=20',{credentials:'same-origin'}).then(function(r){seen(r);if(r.ok)return r.json();if(r.status===404||r.status===401||r.status===403){NOTE.gone=!NOTE.ok;NOTE.err='';notePaint();return null}NOTE.err='서버 응답 '+r.status;notePaint();return null}).then(function(d){if(!d)return false;if(d.error){NOTE.err=String(d.error).slice(0,80);notePaint();return false}NOTE.unack=d.unack||0;NOTE.notices=d.notices||[];NOTE.ok=true;NOTE.err='';NOTE.gone=false;notePaint();return true}).catch(function(){NOTE.gone=!NOTE.ok;NOTE.err=NOTE.gone?'':'연결 끊김';notePaint();return false})}var noteTimer=0;function noteNext(){clearTimeout(noteTimer);noteTimer=setTimeout(notePoll,60000)}function notePoll(){clearTimeout(noteTimer);if(document.hidden)return;noteFetch().then(noteNext)}function noteHtml(){if(NOTE.err)return'<h4>알림</h4><div class="em">알림을 불러오지 못했습니다 — '+esc(NOTE.err)+'. 서버가 응답하면 다시 나타납니다.</div>'+'<a class="go" href="/automation">예약 · 자동화 열기 ›</a>';if(!NOTE.notices.length)return'<h4>알림</h4><div class="em">아직 온 알림이 없습니다 — 예약·자동화가 장애를 잡거나 작업이 실패하면 여기에 쌓입니다.</div>'+'<a class="go" href="/automation">예약 · 자동화 열기 ›</a>';var h='<h4>알림<span>안 읽음 '+NOTE.unack+'건</span></h4>';NOTE.notices.forEach(function(v){h+='<div class="li'+(v.ack?'':' un')+'" data-nid="'+v.id+'">'+'<div class="tx"><b>'+esc(CAT[v.category]||v.category||'알림')+'</b>'+esc(v.message||'')+'<div class="t">'+esc(ago(v.at))+'</div></div>'+(v.ack?'':'<button type="button" class="ok">확인</button>')+'</div>'});return h+'<a class="go" href="/automation">예약 · 자동화에서 모두 보기 ›</a>'}function noteOpen(btn){var box=popOpen(btn,noteHtml());if(!box)return;box.addEventListener('click',function(e){var b=e.target.closest?e.target.closest('.ok'):null;if(!b)return;var row=b.closest('.li'),id=+row.getAttribute('data-nid'),nx=null;b.disabled=true;fetch('/api/automation/ack',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({id:id})}).then(function(){row.classList.remove('un');nx=box.querySelector('.ok:not([disabled])');b.remove();try{(nx||btn).focus()}catch(e){}noteFetch()}).catch(function(){b.disabled=false})})}function whoHtml(me){var h='<h4>내 정보</h4>';h+='<div class="kv"><span>이름</span><b>'+esc(me.name||me.login||'')+'</b></div>';h+='<div class="kv"><span>ID</span><b>'+esc(me.login||'')+'</b></div>';h+='<div class="kv"><span>권한</span><b>'+esc(me.role_ko||'')+'</b></div>';if(me.site&&me.site.name)h+='<div class="kv"><span>사이트</span><b>'+esc(me.site.name)+'</b></div>';if(me.dept)h+='<div class="kv"><span>부서</span><b>'+esc(me.dept)+'</b></div>';if(MYB)h+='<div class="kv"><span>화면 판</span><b>'+esc(MYB)+'</b></div>';return h+(me.logout?'<a class="go" href="/logout">로그아웃</a>':'')}function crumb(){var cr=document.getElementById('lt-cr');if(!cr)return;var n=document.querySelector('nav.nav');var on=n?n.querySelector('a.on'):null;var S=' <span>\u203a</span> ',x=window.LT_CRUMB_EXTRA;if(!on||on.getAttribute('data-k')==='home'){cr.innerHTML='<b>\ud648</b>';return}var grp='',k=on;while(k=k.previousElementSibling){if(k.classList&&k.classList.contains('grp')){grp=ttxt(k);break}}var lb=on.querySelector('.lb');cr.innerHTML='<a class="lt-cr-home" href="/#home">\ud648</a>'+S+(grp?esc(grp)+S:'')+(x?'<a href="'+esc(on.getAttribute('href')||'#')+'">'+esc(lb?lb.textContent:ttxt(on))+'</a>'+S+'<b>'+esc(x)+'</b>':'<b>'+esc(lb?lb.textContent:ttxt(on))+'</b>')}function gnb(){var app=document.querySelector('.app');if(!app)return;try{if(!document.getElementById('lt-gnb-css')){var st=window.ltStyleEl();st.id='lt-gnb-css';st.textContent=GST;document.head.appendChild(st)}var bar=document.getElementById('lt-gnb');if(!bar){var h=document.createElement('div');h.innerHTML=GBAR;bar=h.querySelector('#lt-gnb');if(!bar)return;document.body.insertBefore(bar,app)}document.documentElement.classList.add('lt-gnb-on');if(!bar.dataset.ltWired){bar.dataset.ltWired='1';var bell=bar.querySelector('#lt-bell'),who=bar.querySelector('#lt-who');if(bell)bell.addEventListener('click',function(){noteOpen(this)});if(who)who.addEventListener('click',function(){var m=window.LT_ME;if(m)popOpen(this,whoHtml(m))});document.addEventListener('click',function(e){if(POP&&!POP.contains(e.target)&&!(POPOWN&&POPOWN.contains(e.target)))popClose()});window.addEventListener('keydown',function(e){if(e.key==='Escape')popClose(true)});window.addEventListener('resize',function(){popClose()});window.addEventListener('scroll',function(){popClose()},true);document.addEventListener('visibilitychange',function(){if(document.hidden){clearTimeout(noteTimer)}else{notePoll()}});noteFetch().then(noteNext)}var me=window.LT_ME,w=bar.querySelector('#lt-who');if(me&&w){w.hidden=false;w.querySelector('.av').textContent=(me.name||me.login||'?').trim().slice(0,1);w.querySelector('.nm').textContent=me.name||me.login||'';w.title=(me.login||'')+(me.role_ko?' \u00b7 '+me.role_ko:'')}crumb()}catch(e){if(window.console&&console.warn)console.warn('LogTriage: 상단 바 실패 — 화면은 그대로 씁니다',e)}}var ICO={home:'<path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v9.5h13V10"/><path d="M10 19.5v-5h4v5"/>',new:'<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M12 11v6M9 14h6"/>',dash:'<path d="M12 3a9 9 0 1 0 9 9h-9z"/><path d="M15 3.5A9 9 0 0 1 20.5 9H15z"/>',report:'<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h4"/>',hist:'<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',logsearch:'<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/>',rules:'<path d="m8.5 8-4 4 4 4M15.5 8l4 4-4 4M13.5 5.5l-3 13"/>',forms:'<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="M9 12.5h6M9 16h6"/>',pack:'<path d="m12 3 8.5 4.5L12 12 3.5 7.5z"/><path d="m3.5 12 8.5 4.5 8.5-4.5"/><path d="m3.5 16.5 8.5 4.5 8.5-4.5"/>',nms:'<path d="M3 12h4l2.5-6 4 12 2.5-6H21"/>',inv:'<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M8 7h.01M8 17h.01"/>',auto:'<rect x="3.5" y="5" width="17" height="15.5" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/><path d="m9 15 2 2 4-4"/>',board:'<path d="M4.5 5h15v10h-9l-4.5 4v-4h-1.5z"/>',admin:'<circle cx="9" cy="8.5" r="3.5"/><path d="M3 20c.6-3.5 3-5.5 6-5.5s5.4 2 6 5.5"/><path d="m16 11 1.5 1.5L21 9"/>',hub:'<circle cx="12" cy="12" r="2.5"/><circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="m6.5 6.5 3.7 3.7M17.5 6.5l-3.7 3.7M6.5 17.5l3.7-3.7M17.5 17.5l-3.7-3.7"/>',pc:'<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>'};
function svg(k){return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+(ICO[k]||'')+'</svg>'}
var NAV_DEF=[{core:1,items:[['home','홈','/#home'],['new','로그 분석','/#new'],['dash','전체 현황','/#dash']]},
{g:'analysis',t:'분석 · 조회',items:[['report','판정 리포트','/#report'],['hist','분석 이력','/#hist'],['logsearch','로그 검색','/#logsearch']]},
{g:'knowledge',t:'지식 · 룰',items:[['rules','코드 조회','/#rules'],['forms','보고서 양식','/#forms'],['pack','룰팩 · 룰 학습','/#pack']]},
{g:'ops',t:'운영',srv:1,items:[['nms','모니터링','/nms'],['inv','자산 관리','/resources'],['auto','예약 · 자동화','/automation'],['board','게시판','/board']]},
{g:'manage',t:'관리',srv:1,items:[['admin','사용자 · 권한','/admin'],['hub','통합 현황','/hub']]}];
var PATHK={'/nms':'nms','/resources':'inv','/resources/view':'inv','/automation':'auto','/board':'board','/admin':'admin','/hub':'hub'};
function curKey(){var p=location.pathname.replace(/\/+$/,'')||'/';if(p==='/'||p==='/index.html'){var h=(location.hash||'').slice(1);return h||'home'}if(PATHK[p])return PATHK[p];for(var k in PATHK){if(p.indexOf(k+'/')===0)return PATHK[k]}return ''}
function onRoot(){var p=location.pathname;return p==='/'||p==='/index.html'}
function build(){var n=document.querySelector('nav.nav');if(!n||n.dataset.ltBuilt)return;try{var srv=!onRoot()||!!window.LT_SERVER,h='';NAV_DEF.forEach(function(sec){if(sec.srv&&!srv)return;var it=sec.items.map(function(x){return '<a href="'+x[2]+'" data-href="'+x[2]+'" data-k="'+x[0]+'"><span class="ic" data-icon="'+x[0]+'">'+svg(x[0])+'</span><span class="lb">'+x[1]+'</span>'+(x[0]==='nms'?'<span class="badge" id="nmsbadge" hidden></span>':'')+'</a>'}).join('');if(sec.core){h+='<div class="lt-core">'+it+'</div>';return}h+='<button type="button" class="grp" data-grp="'+sec.g+'">'+sec.t+'</button>'+it});n.innerHTML=h;n.dataset.ltBuilt='1';var side=n.closest('.side');if(side&&!side.querySelector('.lt-mode')){var m=document.createElement('div');m.className='lt-mode';m.id='lt-mode';m.hidden=true;m.innerHTML=svg('pc')+'<span></span>';var foot=side.querySelector('.foot');if(foot)side.insertBefore(m,foot);else side.appendChild(m)}}catch(e){if(window.console&&console.warn)console.warn('LogTriage: 메뉴 그리기 실패 — 원래 메뉴를 씁니다',e)}}
function route(extra){var n=document.querySelector('nav.nav');var k=curKey();if(n){[].slice.call(n.querySelectorAll('a[data-k]')).forEach(function(a){var on=a.getAttribute('data-k')===k;a.classList.toggle('on',on);if(on)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current')});if(n.__ltSync)n.__ltSync()}var hb=document.getElementById('lt-home');if(hb)hb.classList.toggle('on',k==='home');if(extra!==undefined)window.LT_CRUMB_EXTRA=extra;crumb()}
window.LT_ROUTE=route;
function homeKey(){if(window.__ltHome)return;window.__ltHome=1;function goHome(e){if(onRoot()&&typeof window.go==='function'){if(e)e.preventDefault();window.go('home');return}if(e)e.preventDefault();location.href='/#home'}document.addEventListener('keydown',function(e){if(e.altKey&&(e.key==='Home'||e.code==='Home')){goHome(e)}});document.addEventListener('click',function(e){var a=e.target&&e.target.closest?e.target.closest('#lt-home,.lt-gnb .b,.lt-cr-home'):null;if(!a||e.ctrlKey||e.metaKey||e.shiftKey||e.button)return;goHome(e)});window.addEventListener('hashchange',function(){route()})}
function boot(){sweepSW();window.addEventListener('pageshow',revived);link();build();homeKey();run();setTimeout(function(){nav();fold();tips();gnb();route()},0);setTimeout(function(){nav();fold();tips();gnb();route()},400)}if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);else boot()})();"""

# ── 포털 상단 바 — 모양과 뼈대는 여기 한 곳에만 둔다 ────────────────────────────
# 서버가 내보내는 화면(_page)에는 HTML 로 바로 박아 첫 그림부터 자리가 잡히게 하고,
# 창 안에서 도는 화면(SHIM)에는 같은 것을 NAV_JS 가 만들어 넣는다. 두 벌로 갈라지지 않게
# 아래 상수를 토큰으로 NAV_JS 에 끼워 넣는다.
GNB_CSS = (
    ":root{--lt-gnb-h:52px}"
    ".lt-gnb{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:12px;"
    "height:var(--lt-gnb-h);padding:0 12px 0 16px;background:#0E1A22;"
    "border-bottom:1px solid rgba(255,255,255,.09);color:#DCE7EE;"
    "font:14px/1.4 'Segoe UI','Malgun Gothic',sans-serif;box-sizing:border-box}"
    "html.lt-gnb-on .app{height:calc(100dvh - var(--lt-gnb-h))}"
    "html.lt-gnb-on .side{padding-top:10px}"
    "html.lt-gnb-on .side .logo,html.lt-gnb-on .lt-me{display:none}"
    ".lt-gnb .b{display:flex;align-items:center;gap:9px;color:#fff;font-weight:800;font-size:15.5px;"
    "text-decoration:none;letter-spacing:-.2px;flex:none}"
    ".lt-gnb .b em{font-style:normal;color:#2DD4CE}"
    ".lt-gnb .b svg{width:26px;height:26px;border-radius:7px;display:block}"
    ".lt-gnb .cr{display:flex;align-items:center;gap:7px;color:rgba(220,231,238,.6);font-size:12.5px;"
    "white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-left:10px;"
    "border-left:1px solid rgba(255,255,255,.12);margin-left:4px}"
    ".lt-gnb .cr b{color:#fff;font-weight:600}"
    ".lt-gnb .sp{flex:1 1 auto}"
    ".lt-ico{display:flex;align-items:center;justify-content:center;width:34px;height:34px;flex:none;"
    "border-radius:99px;border:0;background:none;color:inherit;cursor:pointer;position:relative}"
    ".lt-ico:hover,.lt-ico[aria-expanded=true]{background:rgba(255,255,255,.10)}"
    ".lt-ico svg{width:19px;height:19px;display:block}"
    ".lt-ico.err{color:#FFB4A8}"
    ".lt-ico .n{position:absolute;top:2px;right:0;min-width:16px;height:16px;padding:0 4px;"
    "box-sizing:border-box;border-radius:99px;background:#E0483B;color:#fff;font-size:10.5px;"
    "font-weight:700;line-height:16px;text-align:center}"
    ".lt-who{display:flex;align-items:center;gap:8px;height:34px;padding:0 11px 0 5px;flex:none;"
    "max-width:210px;border-radius:99px;border:1px solid rgba(255,255,255,.14);background:none;"
    "color:inherit;cursor:pointer;font:inherit;font-size:13px}"
    ".lt-who:hover,.lt-who[aria-expanded=true]{background:rgba(255,255,255,.10)}"
    ".lt-who .av{width:24px;height:24px;border-radius:99px;flex:none;display:flex;align-items:center;"
    "justify-content:center;font-size:11px;font-weight:800;color:#04212A;"
    "background:linear-gradient(135deg,#7FD6E6,#2DD4CE)}"
    ".lt-who .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
    ".lt-pop{position:fixed;z-index:60;min-width:268px;max-width:380px;max-height:70vh;overflow:auto;"
    "background:#101C24;color:#DCE7EE;border:1px solid rgba(255,255,255,.14);border-radius:12px;"
    "box-shadow:0 18px 44px rgba(0,0,0,.55);font-size:13px}"
    ".lt-pop h4{margin:0;padding:11px 14px;font-size:11.5px;letter-spacing:.05em;font-weight:700;"
    "color:rgba(220,231,238,.6);border-bottom:1px solid rgba(255,255,255,.08);display:flex;"
    "justify-content:space-between;align-items:center;gap:10px;position:sticky;top:0;background:#101C24}"
    ".lt-pop .li{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;gap:10px;"
    "align-items:flex-start}"
    ".lt-pop .li.un{background:rgba(45,212,206,.08)}"
    ".lt-pop .li .tx{flex:1 1 auto;min-width:0}"
    ".lt-pop .li .tx b{display:block;font-weight:600;color:#fff;margin-bottom:2px;word-break:break-word}"
    ".lt-pop .li .t{color:rgba(220,231,238,.5);font-size:11.5px;margin-top:3px}"
    ".lt-pop .ok{flex:none;border:1px solid rgba(255,255,255,.18);background:none;color:#9FE7F2;"
    "border-radius:7px;padding:3px 8px;font:inherit;font-size:11.5px;cursor:pointer}"
    ".lt-pop .ok:hover{background:rgba(255,255,255,.08)}"
    ".lt-pop .go{display:block;padding:11px 14px;color:#7FD6E6;text-decoration:none;font-weight:600}"
    ".lt-pop .go:hover{background:rgba(255,255,255,.06)}"
    ".lt-pop .em{padding:18px 14px;color:rgba(220,231,238,.6);line-height:1.6}"
    ".lt-pop .kv{padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;"
    "justify-content:space-between;gap:12px}"
    ".lt-pop .kv span{color:rgba(220,231,238,.55)}"
    "@media(max-width:900px){.lt-gnb .cr{display:none}}"
    "@media(max-width:760px){:root{--lt-gnb-h:48px}.lt-gnb{padding:0 8px}html.lt-gnb-on .app{height:auto}}"
)

_GNB_MARK = (
    "<svg viewBox='0 0 32 32' aria-hidden='true'><rect width='32' height='32' rx='7' fill='#0B6E8A'/>"
    "<rect x='6' y='8' width='13' height='11' rx='2.5' fill='#fff' opacity='.92'/>"
    "<path d='M9 12h7M9 15.5h4.5' stroke='#0B6E8A' stroke-width='1.8' stroke-linecap='round'/>"
    "<circle cx='20' cy='19' r='4.6' fill='none' stroke='#2DD4CE' stroke-width='2.4'/>"
    "<path d='m23.4 22.4 2.6 2.6' stroke='#2DD4CE' stroke-width='2.6' stroke-linecap='round'/></svg>"
)
_GNB_BELL = (
    "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.9' "
    "stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
    "<path d='M18 8a6 6 0 1 0-12 0c0 6-2.5 7-2.5 7h17S18 14 18 8'/>"
    "<path d='M13.7 19a2 2 0 0 1-3.4 0'/></svg>"
)
GNB_BAR = (
    '<header class="lt-gnb" id="lt-gnb">'
    '<a class="b" href="/" title="홈 · 대시보드">' + _GNB_MARK + "<span>Log<em>Triage</em></span></a>"
    '<a class="lt-home" id="lt-home" href="/#home" title="홈으로 돌아가기 (Alt+Home)" aria-label="홈으로">'
    + "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>"
    "<path d='M3 11.5 12 4l9 7.5'/><path d='M5.5 10v9.5h13V10'/><path d='M10 19.5v-5h4v5'/></svg><span>홈</span></a>"
    '<div class="cr" id="lt-cr"></div><div class="sp"></div><button type="button" class="lt-find" id="lt-find" title="메뉴 · 분석 · 근거 ID · 에러코드 찾기 (Ctrl+K)" aria-label="찾기 (Ctrl+K)">'
    "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' aria-hidden='true'><circle cx='11' cy='11' r='7'/><path d='m16.5 16.5 4 4'/></svg>"
    '<span>찾기</span><kbd>Ctrl+K</kbd></button><span class="lt-key" title="어느 화면에서든 홈으로">Alt+Home</span>'
    '<button type="button" class="lt-ico" id="lt-bell" aria-label="알림" aria-haspopup="true" '
    'aria-expanded="false" hidden><span class="n" hidden>0</span>' + _GNB_BELL + "</button>"
    '<button type="button" class="lt-who" id="lt-who" aria-haspopup="true" aria-expanded="false" '
    'hidden><span class="av"></span><span class="nm"></span></button></header>'
)
GNB_HTML = '<style id="lt-gnb-css">' + GNB_CSS + "</style>" + GNB_BAR
# 디자인 시스템 v1(gui/_ds.css) — 모든 화면의 </head> 바로 앞. 화면별 스타일보다 뒤라 같은 규칙으로 덮는다
DS_LINK = '<link rel="stylesheet" id="lt-ds" href="/static/_ds.css">'

from .links import okhref_js as _okhref_js   # 바깥 링크 허용 도메인(아이디어 1) — 모든 화면 공통 검사 함수
NAV_JS = _okhref_js() + NAV_JS
NAV_JS = (NAV_JS.replace("@@GNB_CSS@@", json.dumps(GNB_CSS, ensure_ascii=False))
                .replace("@@GNB_BAR@@", json.dumps(GNB_BAR, ensure_ascii=False)))
# Ctrl+K 찾기(2026-10-15) — 모든 화면 공통. 원본은 gui/_palette.js 한 곳(exe 빌드 spec·build_exe.bat 에도 넣는다)
try:
    NAV_JS += "\n" + Path(__file__).with_name("gui").joinpath("_palette.js").read_text(encoding="utf-8")
except OSError:
    pass
# 긴 안내문 접기(17차) — 모든 화면 공통. 원본은 gui/_condense.js 한 곳(exe 빌드 spec 에도 넣는다)
try:
    NAV_JS += "\n" + Path(__file__).with_name("gui").joinpath("_condense.js").read_text(encoding="utf-8")
except OSError:
    pass


SHIM = r"""<script>
(function(){
  %NAV%
  window.LT_SERVER=true;  // ui.html: 서버형 전용 메뉴(인프라 감시·자산 관리) 표시
  window.LT_NATIVE=%NATIVE%;  // 데스크톱(pywebview) 내장 서버 모드: 파일 대화상자는 네이티브 API 사용
  // 막힌 명령은 **그 자리에서** 승인을 요청할 수 있어야 한다(2026-10-01 사용자 지시).
  // 화면마다 붙이지 않고 모든 호출이 지나는 이 길목 한 곳에서 묻는다.
  async function askApproval(j){
    const q=j.request||{};
    if(!window.confirm((j.error||'권한이 없습니다')+'\n\n관리자에게 승인을 요청할까요?'))return;
    const why=window.prompt('왜 필요한지 한 줄로 적어 주십시오 — 관리자가 이 글을 봅니다.','')||'';
    try{
      const rr=await fetch('/api/access/request',{method:'POST',headers:{'Content-Type':'application/json','X-NMS-Request':'1'},credentials:'same-origin',
        body:JSON.stringify({kind:q.kind,want:q.want,action:q.action||'',reason:why})});
      const jj=await rr.json().catch(()=>({}));
      window.alert(jj&&jj.error?('요청하지 못했습니다 — '+jj.error)
        :'승인 요청을 보냈습니다 — 관리자가 승인하면 다시 로그인한 뒤 쓸 수 있습니다.');
    }catch(e){ window.alert('요청하지 못했습니다 — '+e.message); }
  }
  const call=(n)=>async(...args)=>{
    const r=await fetch('/api/'+n,{method:'POST',headers:{'Content-Type':'application/json','X-NMS-Request':'1'},credentials:'same-origin',body:JSON.stringify(args)});
    if(r.status===401){location.href='/login';return {error:'로그인이 필요합니다'};}
    const j=await r.json();
    if(r.status===403&&j&&j.request){ await askApproval(j); }
    return j;
  };
  const api={};
  %NAMES%.forEach(n=>api[n]=call(n));
  // 15차(마스터: '업로드·분석 등 처리 중인 시간 표시'): 올리는 동안 진행률·속도·경과·남은 시간을 오른쪽 아래에 보여 준다.
  // fetch 는 올리기 진행을 알려 주지 않아 XMLHttpRequest 로 보낸다. 파일 이름은 글자로만 넣는다(textContent).
  const fmtB=b=>b>=1073741824?(b/1073741824).toFixed(2)+' GB':b>=1048576?(b/1048576).toFixed(1)+' MB':Math.max(1,Math.round(b/1024))+' KB';
  function upPanel(){let p=document.getElementById('lt-up');
    if(!p){p=document.createElement('div');p.id='lt-up';p.setAttribute('role','status');p.setAttribute('aria-live','polite');
      p.style.cssText='position:fixed;right:18px;bottom:18px;z-index:9998;width:min(400px,calc(100vw - 36px));background:#0F1B24;color:#E6EEF3;border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.35);padding:12px 14px;font-size:12.5px;line-height:1.6';
      p.innerHTML='<div style="display:flex;align-items:center;gap:10px"><span data-k="ic" style="width:30px;height:30px;border-radius:99px;background:rgba(45,212,206,.16);color:#2DD4CE;display:grid;place-items:center;font-weight:800;flex:none">↑</span><b data-k="t" style="font-size:14.5px;flex:1"></b><button type="button" data-k="x" aria-label="닫기" style="all:unset;cursor:pointer;opacity:.6;font-size:16px;padding:0 4px">✕</button></div><div style="margin:9px 0 8px;height:8px;border-radius:99px;background:rgba(255,255,255,.14);overflow:hidden"><i data-k="bar" style="display:block;height:100%;width:0;background:#2DD4CE;transition:width .2s"></i></div><div data-k="f" style="font-size:13px"></div><div data-k="s" style="opacity:.82;border-top:1px solid rgba(255,255,255,.12);margin-top:6px;padding-top:6px"></div>';
      p.querySelector('[data-k="x"]').addEventListener('click',()=>{p.hidden=true;});
      document.body.appendChild(p);}
    clearTimeout(p._hide);p.hidden=false;return p;}
  function put(f,onp){return new Promise(res=>{const x=new XMLHttpRequest();x.open('PUT','/api/upload?name='+encodeURIComponent(f.name));
    x.upload.onprogress=e=>{if(e.lengthComputable)onp(e.loaded);};
    x.onload=()=>{if(x.status===401){location.href='/login';}let j;try{j=JSON.parse(x.responseText);}catch(e){j={error:'응답을 읽지 못했습니다(HTTP '+x.status+')'};}
      if((x.status<200||x.status>299)&&!(j&&j.error))j={error:'서버가 받지 못했습니다(HTTP '+x.status+')'};res(j);};
    x.onerror=()=>res({error:'네트워크 오류로 올리지 못했습니다'});x.send(f);});}
  async function upload(files){
    const out=[];if(!files.length)return out;
    const total=files.reduce((a,f)=>a+f.size,0),t0=Date.now(),p=upPanel(),q=k=>p.querySelector('[data-k="'+k+'"]'),f0=i=>files[i].size;let done=0;
    p.setAttribute('role','status');p.setAttribute('aria-busy','true');   // 진행 중 숫자를 화면 낭독기가 계속 읽지 않게 — 끝날 때 한 번만
    const draw=(i,cur,name)=>{const sent=Math.min(total,done+cur),sec=(Date.now()-t0)/1000,rate=sec>0.3?sent/sec:0,left=rate>0?(total-sent)/rate:0,pct=total?Math.floor(100*sent/total):100;
      q('t').innerHTML=(cur&&cur>=f0(i)?'서버에 저장하는 중':'로그 올리는 중')+' · <span style="color:#2DD4CE">'+pct+'%</span>';q('bar').style.width=pct+'%';
      q('f').textContent='파일 '+(i+1)+'/'+files.length+' · '+name;
      q('s').textContent=fmtB(sent)+' / '+fmtB(total)+(rate?' · '+fmtB(rate)+'/s':'')+' · 경과 '+Math.round(sec)+'초'+(left>=1?' · 남은 약 '+Math.ceil(left)+'초':'');};
    const tick=setInterval(()=>{const s=q('s');if(s)s.textContent=s.textContent.replace(/경과 \d+초/,'경과 '+Math.round((Date.now()-t0)/1000)+'초');},1000);
    try{
      for(let i=0;i<files.length;i++){const f=files[i];draw(i,0,f.name);
        const j=await put(f,n=>draw(i,n,f.name));done+=f.size;
        if(j.error){alert(f.name+': '+j.error);continue;} out.push(j);}
    }finally{clearInterval(tick);}
    const sec=Math.round((Date.now()-t0)/1000);
    q('t').textContent=(out.length===files.length?'올리기 완료':'일부만 올림 ('+out.length+'/'+files.length+')');q('ic').textContent=out.length===files.length?'✓':'!';q('bar').style.width='100%';
    q('f').textContent='파일 '+out.length+'개 · '+fmtB(total);q('s').textContent='걸린 시간 '+(sec<1?'1초 미만':sec+'초')+' — 이제 [즉시 분석 시작]을 누르십시오';
    p.setAttribute('aria-busy','false');p.setAttribute('role',out.length===files.length?'status':'alert');
    p._hide=setTimeout(()=>{p.hidden=true;},6000);
    return out;
  }
  api.pick_logs=()=>new Promise(res=>{const i=document.createElement('input');i.type='file';i.multiple=true;
    i.onchange=async()=>res(await upload([...i.files]));i.click();});
  api.save_html=async(html,name)=>{const b=new Blob([html],{type:'text/html'});const a=document.createElement('a');
    a.href=URL.createObjectURL(b);a.download=name;a.click();return {saved:name};};
  api.open_folder=async(p)=>{window.open('/reports/',"_blank");return {ok:true};};
  api.pick_form_file=()=>new Promise(res=>{const i=document.createElement('input');i.type='file';i.accept='.hwpx';
    i.onchange=async()=>{const l=await upload([...i.files]);res(l[0]?{path:l[0].path}:{cancel:true});};i.click();});
  let packLast=null;   // 처음 보는 서명 키면 지문을 받아 같은 파일로 다시 보낸다
  const packSend=async(rf,kf,fp)=>{const fd=new FormData();fd.append('rpk',rf);fd.append('key',kf);if(fp)fd.append('confirm_fp',fp);
    const r=await fetch('/api/rulepack',{method:'POST',body:fd});return r.json();};
  api.apply_rulepack=(fp)=>{if(fp&&packLast){const [rf,kf]=packLast;packLast=null;return packSend(rf,kf,fp);}
    return new Promise(res=>{const i=document.createElement('input');i.type='file';i.accept='.rpk';
    i.onchange=()=>{const k=document.createElement('input');k.type='file';k.accept='.pub';
      k.onchange=async()=>{packLast=[i.files[0],k.files[0]];res(await packSend(i.files[0],k.files[0],''));};k.click();};i.click();});};
  window.LT_API=api; if(!window.pywebview||!window.pywebview.api) window.pywebview={api};
  document.addEventListener('dragover',e=>e.preventDefault(),true);
  document.addEventListener('drop',async e=>{e.preventDefault();const fs=[...(e.dataTransfer?.files||[])];
    if(fs.length){const l=await upload(fs);if(window.addFiles)addFiles(l);}},true);
})();
</script>"""

LOGIN_HTML = """<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LogTriage 로그인</title>
<style>
body{font-family:"Malgun Gothic",system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:radial-gradient(1100px 620px at 12% 8%,#FBE7EC 0%,rgba(244,247,249,0) 60%),radial-gradient(900px 520px at 92% 96%,#F8EDF1 0%,rgba(244,247,249,0) 55%),#F6F7F9;color:#14212B}
.card{background:#fff;padding:30px 34px 26px;border-radius:16px;box-shadow:0 24px 60px rgba(20,33,43,.14);width:360px;max-width:calc(100vw - 32px);box-sizing:border-box;border:1px solid #E3EAEF}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:18px}.brand h2{margin:0;color:#C12554;font-size:22px}.brand h2 span{color:#E0446E}.brand div div{color:#5B6B77;font-size:12.5px}
.who{display:flex;align-items:center;gap:8px;margin:0 0 14px;padding:9px 12px;border-radius:10px;background:linear-gradient(135deg,#FDF3F6,#FBECF0);font-size:12.5px;color:#2B3B47}
.who svg{flex:none}
label{display:block;font-size:12px;color:#5B6B77;margin:10px 0 4px}
input{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #CBD5DD;border-radius:8px;font-size:14px;font-family:inherit}
input:focus{outline:none;border-color:#C12554;box-shadow:0 0 0 3px rgba(193,37,84,.20)}
.btn{display:block;text-align:center;text-decoration:none;margin-top:16px;width:100%;box-sizing:border-box;padding:12px;background:linear-gradient(180deg,#9C1442,#C12554);color:#fff;border:0;border-radius:9px;font-size:14.5px;font-weight:700;cursor:pointer;box-shadow:0 3px 10px rgba(193,37,84,.32);font-family:inherit}
.btn:hover{filter:brightness(1.06)}.note{font-size:12.5px;color:#5B6B77;line-height:1.6;margin:6px 0 0}
.err{color:#B42318;background:#FEF3F2;border:1px solid #FECDCA;border-radius:8px;padding:8px 10px;margin-top:12px;font-size:12.5px;line-height:1.5}
.alt{margin-top:16px;padding-top:12px;border-top:1px solid #EDF1F4;font-size:12px;text-align:center}.alt a{color:#5B6B77}
</style>
<body><div class="card"><div class="brand">%LOGO%<div><h2>Log<span>Triage</span></h2><div>장애 로그 분석 · 인프라 감시 — 전사</div></div></div>
%FORM%%MSG%</div></body></html>"""
_PORTAL_ICON = '<svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><defs><linearGradient id="lg_p" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9C1442"/><stop offset="1" stop-color="#E0446E"/></linearGradient></defs><rect x="1" y="1" width="30" height="30" rx="8" fill="url(#lg_p)"/><circle cx="16" cy="12.5" r="4.6" fill="#fff"/><path d="M7.5 25c1.4-4.4 4.7-6.6 8.5-6.6s7.1 2.2 8.5 6.6" fill="#fff"/></svg>'



_AGENT_FILES = ("README.txt", "lt-agent-ctl.sh", "lt-agent.sh", "lt-agent-posix.sh", "lt-agent.py", "lt_procs.py", "lt-agent.ps1", "lt-agent.cmd",
                "lt-agent-install.sh", "agent.conf.example")   # /static/ 로 개별 제공 + lt-agent.zip 구성
_agent_zip_cache: dict = {}
_agent_zip_lock = threading.Lock()


# 19차 간편 설치 — 대상 서버가 로그인 없이 받는 것은 '비밀이 없는' 수집기 원본과 설치 스크립트뿐이다.
# 설치 스크립트에는 각 파일의 SHA-256 을 박아 넣고, 화면은 설치 스크립트의 SHA-256 을 명령에 넣어 먼저 확인하게 한다.
_AGENT_SETUP_FILES = ("lt-agent-ctl.sh", "lt-agent.sh", "lt-agent-posix.sh", "lt-agent.py", "lt_procs.py")
_ENROLL_HITS: dict = {}
_ENROLL_LOCK = threading.Lock()


def agent_plain(name: str) -> bytes | None:
    """수집기 원본(토큰 없음) — 줄바꿈은 LF 로(설치 스크립트의 SHA-256 기준과 같은 바이트)."""
    if name not in _AGENT_SETUP_FILES:
        return None
    f = agent_dir() / name
    return f.read_bytes().replace(b"\r\n", b"\n") if f.is_file() else None


def agent_setup_script() -> bytes:
    t = (agent_dir() / "lt-agent-setup.sh").read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    for n in _AGENT_SETUP_FILES:
        b = agent_plain(n)
        if b is None:
            raise FileNotFoundError(n)
        t = t.replace("@@SHA:" + n + "@@", hashlib.sha256(b).hexdigest())
    if "@@SHA:" in t:
        raise ValueError("설치 스크립트 기준값 자리가 남았습니다")
    return t.encode("utf-8")


def enroll_allow(ip: str, now: float | None = None) -> bool:
    """등록 코드 시도 — 보낸 곳마다 10분에 10번, 서버 전체 10분에 120번(코드 맞히기 막기)."""
    now = time.time() if now is None else now
    with _ENROLL_LOCK:
        for k in list(_ENROLL_HITS):
            _ENROLL_HITS[k] = [x for x in _ENROLL_HITS[k] if now - x < 600]
            if not _ENROLL_HITS[k]:
                del _ENROLL_HITS[k]
        if len(_ENROLL_HITS.get(ip, ())) >= 10 or sum(len(v) for v in _ENROLL_HITS.values()) >= 120:
            return False
        _ENROLL_HITS.setdefault(ip, []).append(now)
        return True


def agent_dir() -> Path:
    d = Path(__file__).resolve().parents[1] / "tools" / "agent"
    if not d.exists():
        d = Path(getattr(sys, "_MEIPASS", "")) / "tools" / "agent"
    return d


# 내려받는 스크립트에 주소·토큰을 박아 넣는 자리 — 파일마다 '인자가 없으면 이 값' 형태로 바꾼다.
# 인자를 주면 인자가 이기므로 기존 설치 방법(주소·토큰을 직접 주는 방식)도 그대로 쓸 수 있다.
_AGENT_FILL = {
    "lt-agent.sh": [('URL="${1:?LogTriage 서버 주소 필요}"; TOKEN="${2:?토큰 필요}"',
                     'URL="${1:-%URL%}"; TOKEN="${2:-%TOKEN%}"')],
    "lt-agent-posix.sh": [('"${1:?LogTriage 서버 주소 필요}"', '"${1:-%URL%}"'),
                          ('TOKEN="${2:?토큰 필요}"', 'TOKEN="${2:-%TOKEN%}"')],
    "lt-agent-install.sh": [('URL="${1:?LogTriage 서버 주소 필요 (예: http://10.0.0.5:8088)}"',
                             'URL="${1:-%URL%}"'),
                            ('TOKEN="${2:?토큰 필요 ([모니터링] 등록 화면의 에이전트 토큰)}"',
                             'TOKEN="${2:-%TOKEN%}"')],
    "lt-agent.py": [("    if len(sys.argv) < 3:\n        print(__doc__); return 1\n", ""),
                    ('url, token = argv[1].rstrip("/"), argv[2]',
                     'url = (argv[1] if len(argv) > 1 else "%URL%").rstrip("/")\n'
                     '    token = argv[2] if len(argv) > 2 else "%TOKEN%"')],
    "lt-agent.ps1": [('param([Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Token,',
                      'param([string]$Url="%URL%",[string]$Token="%TOKEN%",')],
}
_AGENT_NOTE = {".sh": "# ", ".py": "# ", ".ps1": "# "}


def agent_fill(name: str, data: bytes, url: str, token: str) -> bytes:
    """스크립트에 이 서버의 주소·토큰을 기본값으로 채워 돌려준다. 규칙이 맞지 않으면 원본 그대로."""
    rules = _AGENT_FILL.get(name)
    if not rules or not token:
        return data
    try:
        t = data.decode("utf-8").replace("\r\n", "\n")    # 줄바꿈부터 맞춘다(원본이 CRLF 면 여러 줄 규칙이 안 맞는다)
    except UnicodeDecodeError:
        return data
    for old, new in rules:
        if old not in t:
            return data          # 스크립트가 바뀌었다 — 토큰을 잘못 넣느니 원본을 준다(시험이 이 경우를 잡는다)
        t = t.replace(old, new.replace("%URL%", url).replace("%TOKEN%", token), 1)
    mark = _AGENT_NOTE.get("." + name.rsplit(".", 1)[-1], "# ")
    lines = t.split("\n")
    at = 1 if lines and lines[0].startswith("#!") else 0
    lines.insert(at, mark + "[주의] 이 파일에는 이 서버의 수집 토큰이 들어 있습니다 — 권한 600 으로 두고 다른 사람과 공유하지 마십시오.")
    lines.insert(at + 1, mark + "        주소·토큰이 이미 채워져 있어 인자 없이 실행할 수 있고, 인자를 주면 그 값이 우선합니다.")
    out = "\n".join(lines)
    if name.endswith((".ps1", ".cmd")):
        out = out.replace("\n", "\r\n")                 # 윈도우용은 CRLF 로 되돌린다
    return out.encode("utf-8")


def agent_zip(url: str, token: str) -> bytes:
    """설치형 에이전트 zip — lt-agent/ 폴더, 텍스트는 LF(.cmd/.ps1 은 CRLF), .sh 는 실행 권한, agent.conf 에 서버 주소·토큰을 채워 넣는다.
    파일이 바뀌면(스탬프) 다시 만들고, 주소·토큰별로 캐시(최대 8개)."""
    d = agent_dir()
    files = [(n, d / n) for n in _AGENT_FILES if (d / n).exists()]
    stamp = tuple((n, f.stat().st_mtime_ns, f.stat().st_size) for n, f in files)
    key = (stamp, url, token)
    with _agent_zip_lock:
        if key in _agent_zip_cache:
            return _agent_zip_cache[key]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        def put(name: str, data: bytes, mtime: float, mode: int):
            zi = zipfile.ZipInfo("lt-agent/" + name, date_time=time.localtime(mtime)[:6])
            zi.external_attr = (mode << 16) | (0x20 if name.endswith((".cmd", ".ps1")) else 0)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
        for n, f in files:
            data = f.read_bytes().replace(b"\r\n", b"\n")
            if n.endswith((".cmd", ".ps1")):
                data = data.replace(b"\n", b"\r\n")
            put(n, data, f.stat().st_mtime, 0o755 if n.endswith(".sh") else 0o644)
        conf = (f"# LogTriage 에이전트 설정 — 토큰이 들어 있으므로 권한 600 을 유지하십시오(lt-agent-ctl.sh 가 자동 적용)\n"
                f"URL={url}\nTOKEN={token}\nINTERVAL=30\nDISK=all\nPROCS=1\n# COLLECTOR=python|bash|posix   (비우면 자동 선택)\n# PROCS=0 이면 계정별 프로세스 현황을 보내지 않음\n").encode("utf-8")
        put("agent.conf", conf, time.time(), 0o600)
    body = buf.getvalue()
    with _agent_zip_lock:
        if len(_agent_zip_cache) >= 8:
            _agent_zip_cache.clear()
        _agent_zip_cache[key] = body
    return body


_req = threading.local()
_SETUP_LOCK = threading.Lock()     # 첫 관리자 계정 만들기는 한 번에 하나만   # 요청 처리 스레드별: loopback(피어가 같은 PC 인지) — 데스크톱 LocalServerApi 가 경로 허용 판단에 사용


class ServerApi(Api):
    """데스크톱 Api 를 서버 환경에 맞게 확장: 파일 대화상자 대신 업로드/서버 경로, 이력 파일 동시 갱신 잠금."""

    def __init__(self, base: Path, allow_dirs: list[Path], db_url: str | None = None):
        super().__init__()
        self._base = base
        self._history_file = base / "incidents.json"
        self._allow = [d.resolve() for d in allow_dirs]
        self._lock = threading.Lock()
        (base / "uploads").mkdir(parents=True, exist_ok=True)
        (base / "incidents").mkdir(exist_ok=True)
        (base / "reports").mkdir(exist_ok=True)
        (base / "data").mkdir(exist_ok=True)
        self.store = Storage(db_url or sqlite_url(base / "data" / "logtriage.db"))
        n = self.store.migrate_from_files(base)
        if n:
            print(f"[LogTriage server] 파일 이력 {n}건을 DB 로 이관했습니다 ({self.store.describe()})", flush=True)
        # ── 인프라 감시(NMS)·자산 관리 — 분석 DB 와 분리된 SQLite. 수집기 스레드는 serve() 에서 시작 ──
        self.nms = NmsStore(base / "data" / "nms" / "nms.sqlite3")
        self.collector = NmsCollector(self.nms)
        self.inventory = ResourceInventory(base / "data" / "inventory" / "resources.sqlite3")
        # 자산 기준의 현장 조정 — 경로는 설치 위치에서만 나온다(요청이 정하지 못한다)
        self.asset_fields_store = asset_custom_mod.Store(base / "data" / "assets" / "fields.sqlite3")
        self.docs = DocStore(base / "data" / "inventory" / "resources.sqlite3")  # 자원 문서(v3): 업로드 엑셀 원본+표

        from .automation import Automation
        from . import rulepack
        from .automation import InstanceLock
        rpk_lock = InstanceLock(base / '.rpk-apply.lock')
        rpk_lock.acquire()
        try:
            rulepack.recover(base)
        finally:
            rpk_lock.release()
        self.automation = Automation(self)
        # ── 전사(r4): 포털 인증·권한·감사, 본사 허브/사이트 전송 ──
        self.actor = threading.local()      # 요청을 처리하는 계정(분석 이력 소유자 기록용)
        self.auth_conf = authmod.load_conf(base)
        self.auth = authmod.AuthStore(base / "data" / "auth" / "auth.sqlite3")
        self.accounts = None
        self.setup_token = ""
        if self.auth_conf and self.auth_conf["mode"] == "local":
            from .accounts import Accounts
            self.accounts = Accounts(self.auth, base, self.auth_conf)
            # 쿠키 정책을 올린 판으로 처음 올라오면 세션을 한 번 비운다 — 브라우저가 들고 있는
            # 옛 쿠키는 SameSite=Lax 그대로이기 때문이다(GPT 지적). 모두 한 번 다시 로그인한다.
            _dropped = self.auth.apply_cookie_policy(base)
            if _dropped:
                authmod._say(f"[LogTriage] 쿠키 정책이 바뀌어 기존 로그인 {_dropped}건을 끊었습니다 —"
                             " 다시 로그인해 주십시오(옛 쿠키는 SameSite=Lax 로 남아 있었습니다).")
            if not self.accounts.list():   # 계정이 하나도 없으면 첫 관리자 계정을 만드는 화면(/setup)을 연다
                self.setup_token = secrets.token_urlsafe(9)
                self._write_setup_code()
        self.oidc = authmod.Oidc(self.auth_conf) if self.auth_conf and self.auth_conf["mode"] == "portal" and self.auth_conf["portal"]["method"] == "oidc" else None
        self.board = Board(base, self.auth)        # 게시판(질문·분석 공유·분석 요청)
        # 읽을 수 없는 hub.json 때문에 **서버가 아예 안 뜨면 안 된다.** 옛 설치를 올릴 때
        # 지난 판에서 남은 설정(없앤 항목·바뀐 규칙)이 새 검사에 걸리면, 업그레이드가 곧
        # 서비스 중단이 된다. 그렇다고 조용히 넘기면 보내던 것이 말없이 멈춘다 —
        # 그래서 **보내지 않고, 멈춘 까닭을 남기고, 크게 말한다.**
        # **단독과 '연동 차단' 은 뜻이 다르다**(GPT 7차). 단독은 사용자가 고른 운영 방식이고,
        # 연동 차단은 본사 연동을 하려 했는데 설정 이상으로 안전하게 막힌 상태다. 같은 'none'
        # 으로 보여 주면, 보내고 있다고 믿는 서버가 조용히 멈춰 있는 것을 아무도 모른다.
        self.hub_degraded = ""
        try:
            self.hub_conf = hubmod.load_conf(base)
        except (ValueError, OSError) as e:
            self.hub_conf = None
            reason = "config_future" if isinstance(e, hubmod.FutureConf) else "config_invalid"
            self.hub_degraded = str(e)
            # **원본은 건드리지 않는다.** 읽을 수 없는 파일을 우리가 짐작해 다시 쓰면
            # 장애 원인과 운영자의 증거를 한꺼번에 없앤다(GPT 7차).
            try:
                hubmod.mark_recovery(base, reason, str(e))
            except OSError:
                pass
            authmod._say(f"[LogTriage] 본사 연동을 켜지 않았습니다({reason}): {e}"
                         " — 원본 파일은 그대로 두었습니다."
                         " 로그 분석·자산·게시판 같은 이 서버의 기능은 그대로 씁니다.")
        # 옛 설치를 올릴 때 **사이트 신원을 승계한다.** 구버전에는 신원 파일이 없었으므로,
        # 이미 본사로 보내 오던 서버가 새 코드에서는 '잠기지 않은 새 설치' 로 보인다 —
        # 그 상태에서 사이트 ID 를 바꾸면 본사에 쌓인 자료와 끊기고 보내는 곳까지 바뀐다(GPT 상 후보).
        # 보낸 적이 없다고 **확인될 때만** 열어 두고, 모르면 잠근다.
        # 옛 설정에 남은 **없앤 항목**을 파일에서도 지운다. 돌고 있는 설정은 이미 안전하지만
        # (allow_http 는 버리고 verify_tls 는 강제로 켠다), 파일에 'verify_tls': false 가 남아
        # 있으면 운영자가 그것을 읽고 "검사가 꺼져 있다" 고 믿는다. 나중에 누가 파일을 그대로
        # 읽는 코드를 쓰면 그 순간 되살아난다(GPT 5차 — 구설정 부활).
        # 다시 적는 것은 **뜻을 온전히 아는 설정일 때만**이다(GPT 7차).
        # load_conf 를 지났다는 것은 지금 틀로 해석됐다는 뜻이고, 모르는 틀은 위에서 이미
        # 걸러졌다. 그래도 조건을 한 번 더 적어 둔다 — 다음 사람이 이 자리를 넓히지 않게.
        if self.hub_conf and not self.hub_degraded:
            try:
                _raw = json.loads((base / "conf" / "hub.json").read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                _raw = None
            if isinstance(_raw, dict) and _raw != self.hub_conf:
                try:
                    hubmod.save_conf(base, self.hub_conf)   # .bak 을 남기고 고른 값으로 다시 적는다
                    authmod._say("[LogTriage] conf/hub.json 에 더 쓰지 않는 항목이 있어"
                                 " 지금 기준으로 다시 적었습니다(옛 파일은 hub.json.bak).")
                except Exception:
                    pass
        _clash = hubmod.identity_conflict(base, self.hub_conf)
        if _clash:
            # 서로 다른 증거가 부딪히면 **자동으로 정하지 않는다**(GPT 5차). 어느 쪽이 맞는지는
            # 본사에 무엇이 쌓여 있는지를 봐야 알 수 있다. 그때까지 보내기를 멈춘다.
            try:
                hubmod.mark_recovery(base, "identity_conflict", _clash)
            except OSError:
                pass
            self.hub_degraded = _clash
            authmod._say("[LogTriage] " + _clash + " 본사 전송을 멈춥니다.")
        _mig = hubmod.migrate_identity(base, self.hub_conf)
        if _mig:
            authmod._say(f"[LogTriage] 이 서버의 사이트 신원을 '{_mig}' 로 승계했습니다 —"
                         " 이전 판에서 본사로 보낸 적이 있어 사이트 ID 를 잠급니다."
                         " 바꾸려면 본사 담당자와 함께 재등록하십시오.")
        self.hub = hubmod.HubStore(base) if self.hub_conf and self.hub_conf["role"] == "central" else None
        if self.hub:
            self.hub.add_site(self.hub_conf["site_id"], self.hub_conf.get("site_name", ""), local=True)
        self.hub_client = hubmod.HubClient(self, self.hub_conf, self.hub) if self.hub_conf else None
        self._hub_lock = threading.Lock()
        if self.auth_conf and self.auth_conf["mode"] == "portal" and not any(x["source"] == "local" for x in self.auth.users()):
            print("[LogTriage server] 통합 로그인 사용 중: 비상용 로컬 관리자가 없습니다: python -m logtriage.auth --base <설치경로> set-admin", flush=True)

    # ── 첫 관리자 계정 만들기(초기 설정) ──
    def set_signup(self, mode: str, actor: str = "") -> dict:
        """직접 가입 방식 바꾸기 — **서비스를 멈추지 않는다.**

        파일(conf/auth.json)과 돌고 있는 프로세스가 들고 있는 값을 함께 바꾼다. 하나만
        바꾸면 화면과 실제 동작이 어긋난다 — 그 어긋남은 '화면은 막는데 서버는 받는' 꼴로
        이미 한 번 겪었다(사이트 ID 잠금).
        """
        from .accounts import SIGNUP, SIGNUP_FROM_SCREEN, conf_of
        from . import authmode as modefile
        mode = str(mode or "").strip().lower()
        if mode not in SIGNUP:
            raise ValueError("가입 방식은 " + " · ".join(SIGNUP) + " 중 하나입니다")
        if mode not in SIGNUP_FROM_SCREEN:
            # 닿을 수 있는 사람이 모두 사용자가 되는 길은 화면에서 켜지 않는다(GPT 20차).
            raise ValueError(
                "'즉시 사용' 은 화면에서 켤 수 없습니다 — 이 서버에 닿을 수 있는 사람이 모두"
                " 들어오는 방식이라, 서버에 들어올 수 있는 사람만 conf/auth.json 의"
                ' local.signup 을 "open" 으로 고쳐 켭니다(서비스 재시작은 필요 없습니다).')
        if not self.accounts:
            raise ValueError("이 서버는 이메일 계정 로그인을 쓰지 않습니다")
        before = self.accounts.conf["signup"]
        if mode == before:
            return {"ok": True, "mode": mode, "before": before, "changed": False}
        modefile.write_local(self._base, "signup", mode)
        # 파일에 적힌 뒤에 메모리를 맞춘다 — 적지 못했으면 바꾸지 않은 것이다.
        loc = dict((self.auth_conf or {}).get("local") or {})
        loc["signup"] = mode
        if self.auth_conf is not None:
            self.auth_conf["local"] = conf_of({"local": loc})
        self.accounts.conf = conf_of({"local": loc})
        self.auth.audit(actor or "(admin)", "", "signup.mode", "", f"{before} -> {mode}")
        return {"ok": True, "mode": mode, "before": before, "changed": True}

    def _write_setup_code(self) -> None:
        """1회용 초기 설정 코드를 설치 폴더에도 남긴다 — 로그를 보기 어려운 환경에서도 첫 계정을 만들 수 있게(2026-09-22)."""
        fa = (self.auth_conf or {}).get("first_admin", "")
        try:
            p = self._base / "conf" / "setup-code.txt"
            p.parent.mkdir(parents=True, exist_ok=True)
            body = ("LogTriage 초기 설정 코드 (1회용)\n\n"
                    f"코드 : {self.setup_token}\n"
                    f"주소 : http://<서버주소>:<포트>/setup?t={self.setup_token}\n"
                    + (f"첫 관리자 : {fa} — 이 계정의 비밀번호만 정하면 등록이 끝납니다\n" if fa else "")
                    + "\n이 코드를 아는 사람이 이 서버의 첫 관리자가 됩니다 — 아무에게나 알리지 마십시오.\n"
                      "같은 PC 에서 열어도 코드가 필요합니다(앞단 프록시 뒤에서는 접속 주소로\n"
                      "'서버에 앉은 사람' 을 가려낼 수 없기 때문입니다).\n"
                      "관리자 계정을 만들면 이 파일은 지워집니다.\n")
            # **만드는 순간부터** 0600 이어야 한다. 먼저 쓰고 나중에 권한을 고치면 그 사이에
            # 다른 사용자가 읽을 수 있는 파일로 존재한다(GPT 23차).
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(body)
            try:
                os.chmod(p, 0o600)      # 이미 있던 파일을 덮어쓴 경우를 위해 한 번 더
            except OSError:
                pass
        except OSError:
            pass

    def setup_close(self) -> None:
        """첫 계정이 생기면 초기 설정 화면과 코드를 함께 닫는다."""
        self.setup_token = ""
        try:
            (self._base / "conf" / "setup-code.txt").unlink()
        except OSError:
            pass

    # ── 분석 이력·이벤트 원본: DB ──
    def _save_history(self, result):
        who = getattr(self.actor, "login", "")
        if who:
            result["owner"] = who                      # 이력의 주인 — 다른 계정에게는 IP·호스트명을 가려서 보여 준다
            result["owner_name"] = getattr(self.actor, "name", "") or ""
        site = (self.hub_conf or {}).get("site_id", "") if getattr(self, "hub_conf", None) else ""
        with self._lock:
            # 본문(JSON)에만 두면 '내가 한 분석' 도 '우리 사이트 건' 도 찾을 수 없다 — 칼럼으로도 남긴다
            self.store.save_incident(result, actor={"login": who,
                                                    "name": getattr(self.actor, "name", "") or ""},
                                     site=site)
            self.store.import_events(result["id"], self._base / "incidents" / f"{result['id']}.jsonl")

    def history(self):
        try:
            self._history_drop()   # 10차 ⑤: 첫 확인 전에 지난 표시와 대조(그 뒤 표시를 갱신)
            hist = self.store.history()
            for h in hist:
                if h.get("name") == self._LEGACY_NAME:
                    h["name"] = ""
            self._hist_error = ""
            self._mark_history(self.store.incident_count())
            return hist
        except Exception as e:   # 10차 ②·GPT 76차 P0-02: 예전엔 오류를 삼키고 200 + [] — 화면이 '이력 없음'으로 보였다. 오류로 알린다(자세한 것은 진단·기록에)
            self._hist_error = f"{type(e).__name__}: {e}"
            import logging as _lg
            _lg.getLogger(__name__).warning("history read failed: %s", self._hist_error)
            raise ValueError(f"분석 이력을 읽지 못했습니다({type(e).__name__}) — '이력 없음'이 아닙니다. 환경 점검 띠를 확인하십시오") from e

    def _history_status(self):
        where = str(getattr(self.store, "path", "") or "") or "PostgreSQL"
        try:
            return {"count": self.store.incident_count(), "error": getattr(self, "_hist_error", ""), "where": where}
        except Exception as e:   # noqa: BLE001
            return {"count": None, "error": f"{type(e).__name__}: {e}", "where": where}

    def _history_ids(self) -> set:
        return self.store.incident_ids()

    def restore_legacy_history(self):
        """10차 ④: 데스크톱 시절 이관 파일(incidents.json.migrated)에만 남은 분석을 이력으로 다시 넣는다(관리자).
        이미 있는 id 는 건너뛰고, 원문 이벤트는 없어 로그 검색은 되지 않는다. 이관 파일은 그대로 둔다."""
        p = self._base / "incidents.json.migrated"
        try:
            rows = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return {"error": f"이관 파일을 읽지 못했습니다: {e}"}
        if not isinstance(rows, list):
            return {"error": "이관 파일 형식이 목록이 아닙니다"}
        from .safe_backup import export_database   # GPT 76차 P1-03: 가져오기 전에 지금 DB 를 통째로 떠 둔다
        bk = self._base / "backups" / f"before-legacy-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl"
        try:
            export_database(self.store, bk)
        except Exception as e:   # noqa: BLE001
            return {"error": f"가져오기 전 백업에 실패해 멈췄습니다: {type(e).__name__}"}
        before = self.store.incident_count()
        have, n, skip = self.store.incident_ids(), 0, 0
        for r in rows:
            if not isinstance(r, dict) or not r.get("id") or r["id"] in have or not r.get("analyzed_at"):
                skip += 1
                continue
            self.store.save_incident(r, actor={"login": "legacy-restore", "name": "이관 파일 복원"})
            have.add(r["id"])
            n += 1
        after = self.store.incident_count()
        if after != before + n:
            return {"error": f"가져온 뒤 건수가 맞지 않습니다({before}+{n}≠{after}) — 백업 {bk.name} 으로 되돌릴 수 있습니다", "backup": bk.name}
        self._mark_history(after)
        return {"restored": n, "skipped": skip, "backup": bk.name}

    def log_incidents(self):
        avail = self.store.incidents_with_events()
        return [{"id": h["id"], "name": h.get("name", ""), "at": h.get("analyzed_at", ""), "owner": h.get("owner", "")}
                for h in self.history() if h.get("id") in avail]

    def _iter_events(self, incident_id: str):
        r = self.store.search_events(incident_id, "", "", "", 200_000)
        for e in r.get("rows", []):
            yield e

    def search_logs(self, incident_id: str, query: str = "", severity: str = "", layer: str = "", limit: int = 300,
                    t_from: str = "", t_to: str = ""):
        try:
            return self.store.search_events(incident_id, query, severity, layer, int(limit), t_from or "", t_to or "")
        except Exception as e:
            return {"error": str(e)}

    def _allowed(self, p: Path) -> bool:
        rp = p.resolve()
        roots = self._allow + [self._base / "uploads"]
        if any(rp.is_relative_to(r.resolve()) for r in roots):
            return True
        return self._sample_path(p)

    def _in_roots(self, p: Path) -> bool:
        rp = Path(p).resolve()
        return any(rp.is_relative_to(r.resolve()) for r in self._allow + [self._base / "uploads"])

    def _sample_path(self, p: Path) -> bool:
        """12차(PC·리눅스 같은 기능): 엔진과 함께 온 합성 견본만 — 견본 폴더 바로 아래·정해진 이름·링크 아님. 그래야 리눅스 서버에서도
        '견본으로 30초 체험'이 된다(전에는 견본이 허용 경로 밖이라 목록이 비어 단추가 안 보였다). 내용 지문은 분석 때 _sample_bytes 가 본다."""
        try:
            sr = self._samples_root().resolve()
            rp = Path(p).resolve()
        except OSError:
            return False
        return rp.parent == sr and rp.name in self.SAMPLE_PICK and not Path(p).is_symlink()

    def detect(self, paths):
        out = []
        for p in paths:
            path = Path(p)
            if path.exists() and self._allowed(path):
                out.append({"path": str(path), "name": path.name, "product": detect_product(path), "size": self._fsize(path)})
        return out

    def analyze(self, payload):
        only_sample = False
        for item in payload.get("inputs", []):
            if not self._allowed(Path(item["path"])):
                return {"error": f"허용되지 않은 경로: {item['path']} (업로드 파일 또는 --allow-dir 아래만 가능)"}
            if self._sample_path(Path(item["path"])) and not self._in_roots(Path(item["path"])):
                only_sample = True
                if not Path(item["path"]).is_file():          # 없는 견본 — 경로를 다시 열지 않고 알기 쉬운 말로
                    return {"error": f"파일을 찾을 수 없습니다: {Path(item['path']).name} — 견본 폴더(samples)가 빠졌는지 확인하십시오"}
        # GPT 93차 P0(조건부): 견본 규칙으로만 허용된 경로는 내용 지문까지 맞아야 분석한다 — 확인 뒤 링크로 바꿔치기해도
        # 검증한 바이트(임시 사본)만 쓰이고, 지문이 안 맞으면(다른 파일) 경로를 다시 열지 않고 거절한다
        if only_sample and self._sample_bytes([dict(i) for i in payload.get("inputs", [])]) is None:
            return {"error": "합성 견본 내용 지문이 맞지 않아 분석하지 않습니다(견본 폴더의 파일이 바뀌었습니다)"}
        if not _ACTIVE.acquire(blocking=False):
            return {"error": f"동시 분석 한도({MAX_ACTIVE}건) 초과 — 진행 중인 분석이 끝난 뒤 다시 실행하십시오"}
        try:
            with self.automation.guard.shared():   # 분석끼리는 동시 실행(MAX_ACTIVE), 룰팩 교체·백업과는 배타(r2)
                return super().analyze(payload)
        finally:
            _ACTIVE.release()

    def list_dir(self, path: str = ""):
        """서버 로컬 로그 디렉터리 탐색(--allow-dir 아래만). 브라우저 업로드 대신 서버에 있는 로그를 바로 고를 때."""
        try:
            if not path:
                return {"roots": [str(d) for d in self._allow]}
            p = Path(path)
            if not self._allowed(p) or not p.is_dir():
                return {"error": "허용되지 않은 경로"}
            items = []
            for c in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))[:500]:
                try:
                    st = c.stat()
                    items.append({"path": str(c), "name": c.name, "dir": c.is_dir(), "size": st.st_size,
                                  "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")})
                except OSError:
                    continue
            return {"path": str(p), "items": items}
        except Exception as e:
            return {"error": str(e)}

    def save_upload(self, name: str, stream, length: int) -> dict:
        safe = re.sub(r"[^\w.\-가-힣#()]+", "_", Path(name).name)[:120] or "upload.log"
        dest = self._base / "uploads" / f"{datetime.now():%Y%m%d-%H%M%S}_{secrets.token_hex(3)}_{safe}"
        remaining = length
        with open(dest, "wb") as f:
            while remaining > 0:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
        return {"path": str(dest), "name": safe, "product": detect_product(dest), "size": dest.stat().st_size}

    def apply_rulepack_files(self, rpk: Path, key: bytes, confirm_fp: str = "") -> dict:
        try:
            with Api._rc_lock, self.automation.guard.exclusive():   # 룰·코드 로더와 직렬화 + 진행 중 분석이 끝난 뒤 교체(r2)
                try:
                    m = rulepack.apply(rpk, self._base / "rules", key, self._base / "errorcodes", self._base / "manuals",
                                       confirm_fp=confirm_fp or None)
                finally:
                    self._invalidate_rules_cache()
            self._record_pack(m, rpk.name)
            return {"version": m.get("version"), "rule_count": m.get("rule_count"), "signature": m.get("_signature"),
                    "signer_fp": m.get("_signer_fp"), "trust_new": bool(m.get("_trust_new"))}
        except rulepack.TrustNeeded as e:
            return {"need_trust": True, "error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def custom_form_analyze(self, path: str, tpl_id: str = "", *, _hist=None):
        if not path and tpl_id:
            return super().custom_form_analyze("", tpl_id, _hist=_hist)
        p = Path(path)
        try:
            ok = p.resolve().is_relative_to((self._base / "uploads").resolve()) or \
                 p.resolve().is_relative_to((self._base / "report-template" / "custom").resolve())
        except Exception:
            ok = False
        if not ok:
            return {"error": "서식 파일은 브라우저에서 업로드한 파일만 등록할 수 있습니다."}
        return super().custom_form_analyze(path, tpl_id, _hist=_hist)

    def custom_form_preview(self, tpl_id: str, *, _hist=None):
        r = super().custom_form_preview(tpl_id, _hist=_hist)
        if isinstance(r, dict) and r.get("hwpx"):
            r["download"] = f"/reports/{urllib.parse.quote(Path(r['hwpx']).name)}"
        return r

    def stats(self, days=0, *, _hist=None):
        """대시보드 자료 + 오늘의 무인 1차 대응 요약.  days = 기간 칩(0·7·30·90, 그 밖의 값은 전체).

        숫자는 실행 기록에서만 뽑는다. 감시 작업이 하나도 없으면 숫자 대신 그 사실을 알린다.
        요약을 못 만들어도 대시보드 전체가 죽지 않도록 통째로 감싼다.
        _hist = 보는 사람 기준으로 가린 이력(Handler 가 채운다).
        """
        out = super().stats(days, _hist=_hist)
        if not isinstance(out, dict) or out.get("error"):
            return out
        try:
            import json as _json
            import time as _time
            from datetime import datetime as _dt
            mid = _dt.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
            jobs = []
            with self.automation.db() as db:
                rows = [dict(r) for r in db.execute(
                    "SELECT job_id,started,output FROM runs WHERE started>=? ORDER BY started DESC", (mid,))]
                jobs = [dict(r) for r in db.execute("SELECT id,kind,enabled,params FROM jobs")]
            watch = [j for j in jobs if j["kind"] == "log_watch"]
            on = []
            for j in watch:
                try:
                    fu = _json.loads(j["params"] or "{}").get("followup") or {}
                except ValueError:
                    fu = {}
                if j["enabled"] and any(fu.get(k) for k in ("report", "board", "notify")):
                    on.append(j["id"])
            analyzed = crit = acts = 0
            last = 0.0
            for r in rows:
                try:
                    o = _json.loads(r["output"] or "{}")
                except ValueError:
                    continue
                n = len(o.get("analyzed") or [])
                analyzed += n
                if n:
                    last = max(last, r["started"] or 0)
                for f in (o.get("first_response") or []):
                    if f.get("level") == "critical":
                        crit += 1
                    acts += len(f.get("did") or [])
            out["auto"] = {"watch": len(watch), "armed": len(on), "analyzed": analyzed,
                           "critical": crit, "actions": acts,
                           "last": _time.strftime("%Y-%m-%d %H:%M", _time.localtime(last)) if last else ""}
        except Exception:
            pass           # 요약이 없으면 카드만 빠진다 — 대시보드는 그대로 뜬다
        return out

    # ── 업무 절감 효과 — 측정값과 가정값을 갈라서 센다 ──
    # ── 운영 모드 — 단독 / 본사 / 사이트 ──────────────────────────────────────
    def switch_hub(self, conf: dict | None) -> dict:
        """운영 모드를 바꾼다 — **저장과 실제 적용이 어긋나지 않게 한 잠금 안에서.**

        저장만 되고 적용이 실패하면, 지금은 옛 모드인데 **다음 재시작부터 갑자기 보내기
        시작합니다.** 그 반대도 곤란합니다. 그래서 한 잠금 안에서 하고, 중간에 실패하면
        옛 상태로 되돌립니다(GPT 중상).

        옛 전송기가 제때 안 멈추면 **아예 바꾸지 않습니다** — 두 설정이 동시에 살아 있느니
        바꾸지 않는 편이 낫습니다.
        """
        with self._hub_lock:
            before = self.hub_conf
            checked = hubmod.check_conf(conf, base=self._base) if conf else None
            old = self.hub_client
            if old and not old.stop(abandon=True):
                # 멈췄다고 확신할 수 없다 — 버려 두었으므로 더 보내지는 않지만,
                # 이 상태에서 새것을 띄우면 두 전송기가 겹친다. 바꾸지 않는다.
                old.abandoned = False
                old.start()
                raise RuntimeError("지금 본사로 보내는 중이라 모드를 바꾸지 못했습니다 —"
                                   " 잠시 뒤에 다시 해 주십시오")
            try:
                hubmod.save_conf(self._base, checked)
                # **아직 보내지 않는다.** 감사 기록이 남은 뒤에 시작한다 —
                # 자료가 나갔는데 바꾼 근거가 없는 창을 두지 않는다(GPT 중상).
                return self._install_hub(checked, started=False)
            except Exception:
                try:                          # 옛 설정으로 되돌린다
                    hubmod.save_conf(self._base, before)
                    self._install_hub(before)
                except Exception:
                    pass
                raise

    def start_hub(self) -> None:
        """감사 기록까지 끝난 뒤에 보내기를 시작한다."""
        with self._hub_lock:
            if self.hub_client:
                self.hub_client.start()

    RECOVERY = "hub_recovery_required"

    def hub_broken(self) -> str:
        """본사 연동이 멈춰 있는가 — 사람이 읽을 까닭을 돌려준다(아니면 빈 글자).

        옛 판이 남긴 글자만 있는 표식도 그대로 읽는다.
        """
        r = hubmod.read_recovery(self._base)
        if not r:
            return ""
        why, detail = str(r.get("why") or ""), str(r.get("detail") or "")
        return (why + (" — " + detail.splitlines()[0] if detail else "")).strip()

    def hub_recovery(self) -> dict:
        """멈춤 표식 그대로 — 까닭 코드·시각·설정 지문(비밀은 없다)."""
        return hubmod.read_recovery(self._base)

    def hub_state(self) -> str:
        """지금 본사 연동이 어떤 상태인가 — **단독과 '차단' 을 구분한다.**

        단독   사용자가 정상적으로 고른 운영 방식
        차단   본사 연동을 하려 했는데 설정 이상으로 안전하게 막힌 상태
        같은 'none' 으로 보여 주면, 보내고 있다고 믿는 서버가 조용히 멈춰 있는 것을
        아무도 모른다(GPT 7차).
        """
        if self.hub_broken():
            return "degraded"
        return (self.hub_conf or {}).get("role", "none")

    def clear_recovery(self) -> dict:
        """멈춤 표식을 풀고 **그 자리에서** 보내기를 다시 세운다 — 재기동하지 않는다.

        콘솔 명령과 **같은 검사**를 지난다. 설정을 고치지 않았으면 풀지 않는다 —
        같은 일을 또 겪는 길이기 때문이다.
        """
        with self._hub_lock:
            rec = hubmod.read_recovery(self._base)
            if not rec:
                return {"ok": True, "note": "멈춤 표식이 없습니다"}
            d = hubmod.state_report(self._base)
            if not d["ok"]:
                bad = [c["name"] + (f" — {c['note']}" if c["note"] else "")
                       for c in d["checks"] if not c["ok"]]
                raise ValueError("아직 풀 수 없습니다 — " + " / ".join(bad))
            (self._base / "data" / hubmod.RECOVERY_FILE).unlink(missing_ok=True)
            # 설정을 다시 읽어 그 자리에서 세운다. 못 읽으면 표식을 되돌린다.
            try:
                conf = hubmod.load_conf(self._base)
            except Exception as e:                       # noqa: BLE001
                hubmod.mark_recovery(self._base, "config_invalid", str(e))
                raise ValueError(f"설정을 읽지 못해 되돌렸습니다: {e}") from None
            self.hub_degraded = ""
            self._install_hub(conf, started=False)
            return {"ok": True, "was": rec.get("reason", ""), "mode": hubmod.public_conf(
                self.hub_conf, hubmod.trusted(self._base))}

    def reset_identity(self, new_site: str, new_token: str = "") -> dict:
        """사이트 신원을 바꾼다 — **본사와 함께 재등록한 뒤에** 쓰는 길이다.

        화면에서 사이트 ID 칸을 그냥 고치는 것과 다르다. 이것은 결과를 알고 하는 별도 행위라
        따로 두고, 관리자만, 감사에 남기고, 옛 이름을 함께 적는다.
        설정의 사이트 ID 도 같이 맞춘다 — 둘이 어긋나면 다음 기동에서 멈춘다.
        """
        new_site = str(new_site or "").strip()
        if not hubmod.SITE_RE.match(new_site):
            raise ValueError("사이트 ID 는 영문·숫자·_- 1~32자입니다")
        with self._hub_lock:
            was = hubmod.locked_site(self._base)
            if was == new_site:
                return {"ok": True, "note": f"이미 '{new_site}' 입니다"}
            conf = dict(self.hub_conf or {})
            # **옛 토큰을 물려주지 않는다.** 'HQ' 로 쓰던 토큰을 들고 'BUSAN' 으로 이름만
            # 바꿔 보내면, 앞서 막아 둔 경계("보내는 곳이나 사이트가 바뀌면 새 토큰")를
            # 비켜 가는 것이다 — 실제로 그렇게 돌고 있었다(GPT 9차 상 등급).
            new_token = str(new_token or "").strip()
            if conf.get("role") == "site" and not new_token:
                raise ValueError(
                    "사이트 신원을 바꾸려면 **새 사이트 토큰**이 필요합니다 —"
                    f" 본사에서 '{new_site}' 로 재등록하고 받은 토큰을 넣어 주십시오."
                    " 쓰던 토큰을 새 이름으로 물려주지 않습니다")
            # **차례가 중요하다.** 신원을 먼저 적고 설정을 뒤에 적다가 저장이 실패하면,
            # 신원은 새 이름인데 설정과 토큰은 옛 것인 **혼합 상태**가 남는다(실제로 그랬다).
            # 다음 기동에서 어긋남으로 잡혀 송신은 멈추지만, 서버는 망가진 채로 남는다.
            # 그래서 설정을 먼저 고르고 저장한 뒤 신원을 적고, 신원 적기가 실패하면
            # 설정을 되돌린다 — 하나라도 실패하면 **아무것도 바뀌지 않는다**(GPT 9차).
            before_conf = dict(self.hub_conf) if self.hub_conf else None
            if conf:
                conf["site_id"] = new_site
                if new_token:
                    conf["hub_token"] = new_token
                checked = hubmod.check_conf(conf, base=self._base)   # 먼저 고른다(저장 없음)
                hubmod.save_conf(self._base, checked)
            try:
                hubmod.set_identity(self._base, new_site, previous=was, actor=self._who_now())
            except Exception:
                if conf:                                            # 설정을 되돌린다
                    try:
                        hubmod.save_conf(self._base, before_conf)
                    except Exception:
                        pass
                raise
            if conf:
                self._install_hub(hubmod.load_conf(self._base), started=False)
            return {"ok": True, "was": was, "now": new_site}

    def _who_now(self) -> str:
        a = getattr(self, "actor", None)
        return (getattr(a, "login", "") or "") or "(알 수 없음)"

    def rollback_hub(self, before: dict | None) -> None:
        """바꾸지 않은 것으로 되돌린다 — **되돌리기까지 실패하면 손을 놓지 않는다.**

        조용히 넘어가면 설정 파일과 실제로 도는 것이 어긋난 채 계속 돈다. 표식을 남기고
        보내기를 멈춘다 — 사람이 확인해야 풀린다(GPT 중상).
        """
        with self._hub_lock:
            try:
                hubmod.save_conf(self._base, before)
                self._install_hub(before)
                return
            except Exception as e:
                try:
                    if self.hub_client:
                        self.hub_client.stop(abandon=True)
                    self.hub_client = None
                except Exception:
                    pass
                try:
                    d = self._base / "data"
                    d.mkdir(parents=True, exist_ok=True)
                    # 까닭 코드를 남긴다 — 설정 오류·신원 충돌과 **복구 절차가 다르다**(GPT 7차)
                    hubmod.mark_recovery(
                        self._base, "rollback_failed",
                        f"바꾸다 실패했고 되돌리는 것도 실패했습니다: {e}."
                        " 설정과 실제 동작이 어긋났을 수 있습니다")
                except OSError:
                    pass

    def _install_hub(self, conf: dict | None, started: bool = True) -> dict:
        """새 설정으로 세우고 보내기 시작한다 — 멈추는 일은 switch_hub 가 이미 했다.

        central 이 아니면 수집 저장소를 **닫아 둔다**(파일은 남긴다). 파일이 있는지로
        판단하면, 사이트로 바꾼 뒤에도 옛 통합 자료를 지금 자료처럼 보여 준다(GPT 중상).
        """
        self.hub_conf = conf
        self.hub = hubmod.HubStore(self._base) if conf and conf["role"] == "central" else None
        if self.hub and conf:
            try:
                self.hub.add_site(conf["site_id"], conf.get("site_name", ""), local=True)
            except Exception:
                pass              # 이미 있으면 그대로 쓴다
        self.hub_client = hubmod.HubClient(self, conf, self.hub) if conf else None
        if self.hub_client and started:
            self.hub_client.start()
        return hubmod.public_conf(conf, hubmod.trusted(self._base))

    # ── 자산 기준 항목 — 우리가 요구하는 것 ──────────────────────────────────────
    def _asset_overlay(self, asset_type: str = "") -> tuple:
        """현장 조정(더한 항목·바뀐 등급)을 **서버 금고에서만** 읽는다.

        요청이 항목 목록을 실어 보내게 하면, 아무나 '비밀번호' 라는 항목이 있는 기준을 만들어
        그 이름으로 파일을 읽힐 수 있다. 그래서 바깥에서 들어오는 길을 두지 않는다.
        """
        try:
            st = self.asset_fields_store
            extra = [f for f in st.fields()
                     if "*" in f["apply_to"] or (asset_type and asset_type in f["apply_to"])]
            return extra, st.levels()
        except Exception:
            return [], {}      # 조정을 못 읽어도 기본 기준으로는 돌아간다

    def asset_spec(self, asset_type: str = ""):
        """유형별 기준 항목 한 벌 — 화면과 파일 읽기가 같은 것을 본다."""
        try:
            extra, levels = self._asset_overlay(asset_type or "")
            return asset_spec_mod.spec(asset_type or "", extra=extra, levels=levels)
        except Exception as e:
            return {"error": str(e)}

    def asset_check(self, values: dict, asset_type: str = ""):
        """빈 필수 항목을 '왜 필요한지' 와 함께 — 저장을 막지는 않는다."""
        try:
            extra, levels = self._asset_overlay(asset_type or "")
            return asset_spec_mod.check(values or {}, asset_type or "", extra=extra, levels=levels)
        except Exception as e:
            return {"error": str(e)}

    def asset_map(self, headers: list, asset_type: str = "", samples: dict = None):
        """남이 준 표의 머리글을 우리 항목에 맞춘다 — 확실·추정·모름을 그대로 돌려준다."""
        try:
            if not isinstance(headers, list):
                raise ValueError("머리글은 목록이어야 합니다")
            extra, levels = self._asset_overlay(asset_type or "")
            return asset_spec_mod.map_headers(headers[:200], asset_type or "", samples or None,
                                              extra=extra, levels=levels)
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"머리글을 맞추지 못했습니다: {e}"}

    # ── 기준 손보기 — 현장이 항목을 더하고 등급을 올리거나 내린다(관리자) ──────
    def asset_fields(self):
        """지금 이 사이트의 기준이 기본에서 무엇이 달라져 있는지."""
        try:
            st = self.asset_fields_store
            known = {}
            for t in list(asset_spec_mod.types()) + [""]:
                for f in asset_spec_mod.fields(t):
                    known.setdefault(f["id"], f)
            levels = st.levels()
            return {"custom": st.fields(), "levels": levels,
                    "level_labels": asset_spec_mod.LEVEL,
                    "kinds": dict(asset_custom_mod.KIND_KO),
                    "from_file": list(asset_custom_mod.FROM_FILE),
                    # 우리가 지키는 바닥 — 화면이 내리는 선택지를 아예 안 만들게(403 을 보게 하지 않는다)
                    "floor": dict(asset_custom_mod.FLOOR),
                    "types": asset_spec_mod.types(),
                    "one_of": {k: v["label"] for k, v in asset_spec_mod.ONE_OF.items()},
                    "changed": [{"id": i, "label": known.get(i, {}).get("label", i),
                                 "base": known.get(i, {}).get("level", ""), "now": lv}
                                for i, lv in levels.items() if i in known],
                    # 누가 바꿨는지는 계정 아이디가 들어 있는 감사 기록이다 — 운영 권한부터 보인다
                    "changes": st.changes(50) if self._level() >= 2 else [],
                    "changes_hidden": self._level() < 2,
                    "max_fields": asset_custom_mod.MAX_FIELDS,
                    "never": {k: v["label"] for k, v in asset_spec_mod.DROP.items()}}
        except Exception as e:
            return {"error": str(e)}

    def _level(self) -> int:
        """요청 계정의 권한 세기 — 감사 정보를 누구까지 보일지 가르는 데 쓴다."""
        return authmod.ROLES.get(getattr(self.actor, "role", "") or "", 0)

    def _who(self) -> str:
        """기준을 바꾼 사람 — 누가 필수를 내렸는지 나중에 되짚을 수 있어야 한다."""
        login = getattr(self.actor, "login", "") or ""
        name = getattr(self.actor, "name", "") or ""
        return (login + ("/" + name if name else "")) or "(알 수 없음)"

    def asset_field_add(self, label: str = "", kind: str = "text", level: str = "advised",
                        why: str = "", aliases: list = None, apply_to: list = None,
                        example: str = ""):
        """항목을 더한다 — 받지 않기로 한 것은 여기서도 거절한다."""
        try:
            if not isinstance(aliases or [], list) or not isinstance(apply_to or [], list):
                raise ValueError("별칭과 적용 유형은 목록이어야 합니다")
            return self.asset_fields_store.add_field(
                label, kind, level, why, [str(a) for a in (aliases or [])][:20],
                [str(t) for t in (apply_to or [])][:20], example, actor=self._who())
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"항목을 만들지 못했습니다: {e}"}

    def asset_field_rename(self, field_id: str = "", label: str = ""):
        """이름만 바꾼다 — id 는 그대로여서 이미 등록된 자산이 깨지지 않는다."""
        try:
            return self.asset_fields_store.rename_field(str(field_id), label, actor=self._who())
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"이름을 바꾸지 못했습니다: {e}"}

    def asset_field_level(self, field_id: str = "", level: str = ""):
        """등급을 올리거나 내린다 — 기본 항목도 된다. 무엇을 바꿨는지 남는다."""
        try:
            return self.asset_fields_store.set_level(str(field_id), str(level), actor=self._who())
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"등급을 바꾸지 못했습니다: {e}"}

    def asset_field_remove(self, field_id: str = ""):
        """쓰지 않음으로 둔다 — 지우지 않는다(그 항목으로 등록된 자산이 있을 수 있다)."""
        try:
            return self.asset_fields_store.remove_field(str(field_id), actor=self._who())
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"항목을 내리지 못했습니다: {e}"}

    # ── 개인화 홈 — 로그인하자마자 '내가 할 일' ─────────────────────────────────
    def home(self, days: int = 30):
        """홈 화면 자료. 조각마다 따로 감싸 하나가 실패해도 나머지는 그대로 나온다."""
        import datetime as _dt
        me = {"login": getattr(self.actor, "login", "") or "",
              "name": getattr(self.actor, "name", "") or ""}
        now = _dt.datetime.now()
        month_start = now.replace(day=1, hour=0, minute=0, second=0,
                                  microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
        out = {"me": me, "now": now.strftime("%Y-%m-%d %H:%M"), "errors": {},
               "todo": {}, "acting": [], "open": [], "mine": [], "asset": {}, "counts": {}}

        def part(key, fn):
            try:
                return fn()
            except Exception as e:                      # 한 조각 실패가 홈 전체를 막지 않는다
                out["errors"][key] = str(e)[:200]
                return None

        c = part("counts", self.store.status_counts)
        if c is not None:
            out["counts"] = c
            out["todo"]["acting"] = c.get("acting", 0)
            out["todo"]["open"] = c.get("open", 0)
        r = part("acting", lambda: self.store.by_status("acting", 8))
        if r is not None:
            out["acting"] = r
        r = part("open", lambda: self.store.by_status("open", 8))
        if r is not None:
            out["open"] = r
            out["todo"]["open_crit"] = sum(1 for x in r if x.get("critical"))
        r = part("mine", lambda: self.store.by_actor(me["login"], 6))
        if r is not None:
            out["mine"] = r
        r = part("asset", lambda: {"month": self.store.asset_counts(month_start),
                                   "total": {"incidents": self.store.count()}})
        if r is not None:
            out["asset"] = r
        r = part("unack", lambda: self.automation.notices(1)["unack"])
        if r is not None:
            out["todo"]["unack"] = r
        r = part("jobs", lambda: [j for j in (self.automation.status().get("jobs") or [])])
        if r is not None:
            out["todo"]["job_failed"] = sum(1 for j in r if j.get("state") == "failed")
            out["todo"]["job_total"] = len(r)
        return out

    # ── 조치 기록 — '실제로 무엇을 해서 해결했는지' (자산화) ──────────────────────
    def actions(self, incident_id: str):
        """이 분석 건에 적힌 실제 조치들. 화면이 고를 수 있게 갈래·결과·상태 표도 함께 준다."""
        try:
            return {"incident_id": incident_id, "actions": self.store.actions(incident_id),
                    "kinds": storage.ACTION_KIND, "results": storage.ACTION_RESULT,
                    "statuses": storage.STATUS}
        except Exception as e:
            return {"error": str(e)}

    def action_add(self, incident_id: str, what: str, kind: str = "etc",
                   result: str = "pending", minutes=None, note: str = ""):
        """실제로 한 조치 한 건을 남긴다 — 누가 적었는지는 서버가 붙인다(화면 입력을 믿지 않는다)."""
        who = getattr(self.actor, "login", "")
        try:
            aid = self.store.add_action(
                incident_id, what, kind=kind, result=result, minutes=minutes, note=note,
                actor={"login": who, "name": getattr(self.actor, "name", "") or ""})
            return {"id": aid, "actions": self.store.actions(incident_id)}
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"조치 기록을 남기지 못했습니다: {e}"}

    def set_status(self, incident_id: str, status: str):
        try:
            if not self.store.set_status(incident_id, status):
                return {"error": "그런 분석 건이 없습니다"}
            return {"ok": True, "status": status}
        except ValueError as e:
            return {"error": str(e)}

    def past_actions(self, incident_id: str, limit: int = 5):
        """같은 증상에서 지난번 우리가 한 조치 — 규칙이 제안한 조치보다 이것을 먼저 보여 준다."""
        try:
            rec = self.store.get(incident_id) or {}
            sig = storage.signature_of(rec) if rec else ""
            return {"signature": sig,
                    "actions": self.store.past_actions(sig, exclude=incident_id, limit=limit)}
        except Exception as e:
            return {"error": str(e)}

    # ── 1차 명령 현장 피드백(아이디어 5)·결과 해석(8)·사후 원인(12) ──
    def kb_feedback(self, rule_id: str, cmd_hash: str, result: str, version: str = "", incident_id: str = ""):
        """명령 한 줄이 현장에서 동작했는지 — 명령 지문·결과·판만 받는다(출력·호스트·비밀은 받지 않는다).
        '동작함' 은 명령이 돌았다는 뜻이지 진단이 맞았다는 뜻이 아니다(GPT 55차)."""
        try:
            self.store.add_feedback(rule_id, cmd_hash, result, version,
                                    actor={"login": getattr(self.actor, "login", "")}, incident_id=incident_id)
            return {"ok": True, "summary": self.store.feedback_summary([rule_id]).get(str(rule_id)[:120], {})}
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"피드백을 남기지 못했습니다: {e}"}

    def exec_report(self, incident_id: str, rule_id: str, idx: int, status: str, error_code: str = "", header_line: str = ""):
        """8차 아이디어 6: 현장에서 1차 명령(읽기 전용)을 돌린 결과 — 성공·오류, 오류 코드, **머리글 줄의 칼럼 이름만** 받는다.
        값·호스트·출력은 받지 않는다. 머리글 줄은 한 줄이어야 하고 이름 꼴(영문·숫자·_$#%)이 아닌 낱말이 하나라도 있으면 통째로 거절
        (값이 섞인 줄일 수 있다). 값 한 줄이 우연히 이름 꼴이면 막지 못한다 — 화면이 그 점을 알린다."""
        import hashlib as _h
        import re as _re
        rec = self.store.get(incident_id) or {}
        item = next((c for c in rec.get("checklist") or [] if c.get("rule_id") == rule_id), None)
        try:
            cmd = (item or {}).get("cmds", [])[int(idx)]
        except (IndexError, ValueError, TypeError):
            cmd = None
        if not cmd:
            return {"error": "그 판정·명령을 찾지 못했습니다(분석 기록을 다시 여십시오)"}
        if not cmd.get("safe"):
            return {"error": "읽기 전용으로 분류된 명령만 실행 결과를 받습니다"}
        line = str(header_line or "")
        if "\n" in line.strip() or "\r" in line.strip():
            return {"error": "머리글 한 줄만 붙여 넣으십시오(값 줄이 섞이면 받지 않습니다)"}
        heads = [h for h in _re.split(r"[\s|,;]+", line.strip()) if h and not _re.fullmatch(r"[-=+]+", h)]
        st = {"성공": "ok", "ok": "ok", "오류": "error", "error": "error"}.get(str(status), "")
        try:
            self.store.add_exec_report(item.get("code_key") or rule_id, cmd.get("hash") or _h.sha256(cmd.get("cmd", "").encode()).hexdigest()[:16],
                                       st, str(error_code or "").strip(), heads, item.get("product", ""),
                                       ((rec.get("versions_detected") or {}).get(str(item.get("product") or "").split("-")[0]) or ""),
                                       actor={"login": getattr(self.actor, "login", "")}, incident_id=incident_id)
            k = item.get("code_key") or rule_id
            return {"ok": True, "summary": self.store.exec_report_summary([k]).get(k, {})}
        except ValueError as e:
            return {"error": str(e)}

    def link_review_assist(self):
        """9차 ①: 한 건씩 볼 대기 연결을 제품별로 묶고 승인 질문을 준다(관리자)."""
        from . import link_review as LR
        try:
            return LR.assist(Path(self._base))
        except Exception as e:
            return {"error": str(e)}

    def governance_report(self, month: str = ""):
        """9차 ⑫: 관리자 결정 감사 월보 — 연결 승인·반려·묶음 승인, 장애 묶음 변경, 판 지정(담당자 지정), 현장 보고를
        누가·언제·무슨 근거로 했는지 한 달 단위로 모은다(관리자). 판정 통계를 바꾸는 결정을 사람이 정기적으로 다시 보게 하는 고리."""
        import re as _re
        from datetime import datetime as _dt
        from . import link_review as LR
        month = str(month or "").strip() or _dt.now().strftime("%Y-%m")
        if not _re.fullmatch(r"\d{4}-\d{2}", month):
            return {"error": "달은 YYYY-MM 꼴로"}
        lo = _dt.strptime(month + "-01", "%Y-%m-%d").timestamp()
        y, m = map(int, month.split("-"))
        hi = _dt(y + (m == 12), (m % 12) + 1, 1).timestamp()
        base = Path(self._base)
        link = []
        try:
            for ln in (base / LR.LOCAL_FILE).read_text(encoding="utf-8").splitlines():
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                if lo <= float(r.get("ts") or 0) < hi:
                    link.append(r)
        except OSError:
            pass
        out = {"month": month, "link": {}, "link_by": {}, "groups": [], "versions": [], "exec_reports": 0}
        for r in link:
            out["link"][r.get("decision", "")] = out["link"].get(r.get("decision", ""), 0) + 1
            k = f"{r.get('by', '')}|{r.get('decision', '')}"
            out["link_by"][k] = out["link_by"].get(k, 0) + 1
        try:
            with self.store._conn() as c:
                cur = c.cursor()
                cur.execute(self.store._q("SELECT at, actor, incident_id, group_key, reason FROM incident_groups WHERE at >= ? AND at < ? ORDER BY at"), (lo, hi))
                out["groups"] = self.store._rows(cur)
                cur.execute(self.store._q("SELECT at, actor, host, product, instance, version, source FROM host_versions WHERE at >= ? AND at < ? ORDER BY at"), (lo, hi))
                out["versions"] = self.store._rows(cur)
                cur.execute(self.store._q("SELECT COUNT(*) FROM exec_reports WHERE at >= ? AND at < ?"), (lo, hi))
                out["exec_reports"] = int((cur.fetchone() or [0])[0])
        except Exception as e:   # noqa: BLE001 — 저장소 문제를 그대로 알린다
            out["error_store"] = str(e)[:200]
        def q(v) -> str:   # GPT 70차: 사용자 글이 표 구조를 깨지 않게 — | ` 줄바꿈 이스케이프
            return str(v or "").replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("\r", " ").replace("\n", " ")[:80]
        md = [f"# 관리자 결정 감사 — {month}(이 서버 PC 의 지역 시각 기준)\n",
              "## 연결 승인\n", "| 결정 | 건수 |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(out["link"].items())]
        md += ["\n| 결정자 | 결정 | 건수 |", "|---|---|---|"] + [f"| {q(k.split('|')[0])} | {q(k.split('|')[1])} | {v} |" for k, v in sorted(out["link_by"].items())]
        md += ["\n## 장애 묶음 변경(개선 제안의 '서로 다른 장애' 판단을 바꿈)\n", "| 시각 | 결정자 | 분석 건 | 묶음 | 사유 |", "|---|---|---|---|---|"]
        md += [f"| {_dt.fromtimestamp(g['at']).strftime('%m-%d %H:%M')} | {q(g.get('actor'))} | {q(g['incident_id'])} | {q(g.get('group_key') or '(자동으로)')} | {q(g.get('reason'))} |"
               for g in out["groups"]]
        md += ["\n## 판 지정\n", "| 시각 | 결정자 | 호스트 | 제품 | 인스턴스 | 판 | 근거 |", "|---|---|---|---|---|---|---|"]
        md += [f"| {_dt.fromtimestamp(v['at']).strftime('%m-%d %H:%M')} | {q(v.get('actor'))} | {q(v['host'])} | {q(v['product'])} | {q(v.get('instance'))} | {q(v['version'])} | "
               f"{'출력 확인' if v['source'] == 'evidence' else '담당자 지정'} |" for v in out["versions"]]
        md += [f"\n현장 보고 {out['exec_reports']}건. 이 보고는 결정이 옳았는지가 아니라 **누가 무엇을 바꿨는지**를 다시 보게 하는 목록입니다."]
        out["markdown"] = "\n".join(md) + "\n"
        out["groups"] = len(out["groups"])
        out["versions"] = len(out["versions"])
        return out

    _INSTALL: dict = {}

    def install_check(self):
        """9차 아이디어 ⑩: 실행 중인 exe 해시와 설치 기록(install-stamp.json)을 읽기 전용으로 대조한다 — 손으로 바꿔 넣었거나
        V3 복구 등으로 판이 바뀌었으면 화면 띠로 알린다. 실수 방지용이지 보안 경계가 아니다(설치 폴더 쓰기 권한자는 기록도 바꿀 수 있다).
        기동 때 한 번 재고 캐시한다 — 실시간 감시가 아니다(GPT 70차)."""
        import hashlib as _h
        base = Path(getattr(self, "_base", ".") or ".")
        key = str(base)
        hit = self._INSTALL.get(key)
        if hit:
            return hit
        if not getattr(sys, "frozen", False):
            res = {"state": "dev", "note": "개발 실행(포장본 아님) — 대조하지 않음"}
        else:
            sp = Path(sys.executable).parent / "install-stamp.json"
            try:
                st = json.loads(sp.read_text(encoding="utf-8")) if sp.exists() else None
                bad = st is not None and not (isinstance(st, dict) and st.get("gui_sha"))
            except (OSError, ValueError):
                st, bad = None, True
            if bad:
                res = {"state": "broken", "note": "설치 기록(install-stamp.json)이 깨져 읽을 수 없습니다 — 관리자에게 알리십시오"}
            elif not st and _is_standalone(base):
                # 10차 UI: exe 하나만 옮겨 쓰는 단독 실행은 설치 기록이 없는 것이 정상 — 고장처럼 보이는 띠를 띄우지 않는다(진단·칩에서 확인)
                res = {"state": "standalone", "note": "단독 실행 — exe 안 내장 지식으로 펼친 폴더(설치 기록 대조 없음)"}
            elif not st:
                res = {"state": "no_stamp", "note": "설치 기록(install-stamp.json)이 없습니다 — 설치 도구로 설치하지 않은 판입니다"}
            else:
                h = _h.sha256()
                with open(sys.executable, "rb") as f:
                    for b in iter(lambda: f.read(1 << 20), b""):
                        h.update(b)
                me = h.hexdigest().upper()
                want = str(st.get("gui_sha") or "").upper()
                name = Path(sys.executable).name.lower()
                if name == "logtriage-cli.exe":
                    want = str(st.get("cli_sha") or "").upper()
                res = ({"state": "ok", "sha": me[:16], "at": st.get("at", "")} if me == want else
                       {"state": "mismatch", "sha": me[:16], "want": want[:16], "at": st.get("at", ""),
                        "note": "이 실행 파일은 설치 기록과 다른 판입니다 — 손으로 바꿔 넣었거나 되돌리기·백신 복구로 바뀌었을 수 있습니다. 관리자에게 알리십시오"})
        self._INSTALL[key] = res
        return res

    def exec_report_summary(self, vkeys=None):
        try:
            return {"summary": self.store.exec_report_summary([str(x) for x in vkeys][:500] if isinstance(vkeys, list) else None)}
        except Exception as e:
            return {"error": str(e)}

    def version_signals(self):
        try:
            return {"rows": self.store.version_signals(),
                    "note": "'판 다름' 현장 피드백이 서로 다른 장애 2건 이상(같은 장애 재분석은 한 번)에서 나온 호스트·제품입니다 — 판은 자동으로 바꾸지 않습니다. 그 호스트의 실제 판을 확인해 지정하십시오."}
        except Exception as e:
            return {"error": str(e)}

    def incident_group_set(self, incident_ids, group_key=None, reason: str = ""):
        """8차 아이디어 10: 개선 제안의 '서로 다른 장애' 식별을 관리자가 고친다 — 같은 묶음 이름 = 같은 장애(합치기),
        서로 다른 이름 = 다른 장애(나누기), 비우기(None) = 자동 식별로 되돌리기. 이력은 지우지 않는다."""
        try:
            gk = (str(group_key).strip() or None) if group_key is not None else None
            return self.store.set_incident_group(list(incident_ids or []), gk, reason, actor={"login": getattr(self.actor, "login", "")})
        except ValueError as e:
            return {"error": str(e)}

    def incident_groups_list(self, incident_id: str = ""):
        try:
            if incident_id:
                return {"history": self.store.incident_group_history(incident_id)}
            return {"groups": list(self.store.incident_groups().values())}
        except Exception as e:
            return {"error": str(e)}

    def kb_feedback_summary(self, rule_ids=None):
        try:
            ids = [str(x) for x in rule_ids][:500] if isinstance(rule_ids, list) else None
            return {"summary": self.store.feedback_summary(ids)}
        except Exception as e:
            return {"error": str(e)}

    def interpret_output(self, incident_id: str, rule_id: str, idx: int, text: str):
        """붙여 넣은 명령 출력을 그 명령의 판단 기준으로 읽는다 — 저장하지 않는다. 기계로 못 읽으면 '판정 불가'·'사람 판단'."""
        from . import knowledge_quality as KQ
        text = str(text or "")
        if len(text.encode("utf-8", "replace")) > KQ.MAX_INTERPRET:
            return {"error": f"출력이 너무 깁니다({KQ.MAX_INTERPRET // 1024}KB 이하로 잘라 붙여 넣으십시오)"}
        try:
            rec = self.store.get(incident_id) or {}
        except Exception as e:
            return {"error": str(e)}
        item = next((c for c in rec.get("checklist") or [] if c.get("rule_id") == rule_id), None)
        try:
            cmd = (item or {}).get("cmds", [])[int(idx)]
        except (IndexError, ValueError, TypeError):
            cmd = None
        if not cmd:
            return {"error": "그 판정·명령을 찾지 못했습니다(분석 기록을 다시 여십시오)"}
        spec = None
        try:   # 지표 고정(errorcodes/_metrics.yaml) — 판정 키·명령이 맞는 짝만. 나머지는 참고 수치
            base = getattr(self, "_base", None)
            if base:
                spec = KQ.metric_for(KQ.load_metrics(Path(base) / "errorcodes"), (item or {}).get("code_key", ""), cmd.get("cmd", ""))
        except (OSError, ValueError):
            spec = None
        r = KQ.interpret(cmd.get("criterion", ""), text, spec)
        r["criterion"] = cmd.get("criterion", "")
        r["note"] = ((r.get("note") + " · ") if r.get("note") else "") + "기계 해석은 보조입니다 — 명령이 돌았다는 것과 진단이 맞았다는 것은 다릅니다."
        return r

    def postmortem_get(self, incident_id: str):
        try:
            return {"postmortem": self.store.get_postmortem(incident_id), "certainty": storage.CERTAINTY,
                    "verdict_ok": storage.VERDICT_OK}
        except Exception as e:
            return {"error": str(e)}

    def postmortem_set(self, incident_id: str, cause: str, certainty: str, verdict_ok: str, note: str = ""):
        """실제 원인 기록 — 룰을 자동으로 바꾸지 않는다. 관리자가 '판정 적중 검토'에서 보고 사람이 고친다(GPT 55차)."""
        try:
            return {"postmortem": self.store.set_postmortem(incident_id, cause, certainty, verdict_ok, note,
                                                            actor={"login": getattr(self.actor, "login", "")})}
        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"사후 원인을 남기지 못했습니다: {e}"}

    def host_version_set(self, host: str, product: str, version: str, evidence: str = "", instance: str = ""):
        try:
            return {"ok": True, "record": self.store.set_host_version(host, product, version, evidence,
                                                                     actor={"login": getattr(self.actor, "login", "")}, instance=instance)}
        except ValueError as e:
            return {"error": str(e)}


    def version_reevaluate(self, incident_id: str):
        """저장된 분석 건의 1차 명령 판 맞춤을, 지금 기록된 호스트별 판(지정·확인)으로 다시 계산해 돌려준다.
        원래 분석 결과는 고치지 않는다(GPT 60차) — 재평가했다는 이력만 남긴다. 기록이 없는 제품은 원래 추정 그대로."""
        from . import knowledge_quality as KQ
        rec = self.store.get(incident_id) or {}
        if not rec:
            return {"error": "그런 분석 건이 없습니다"}
        hosts = sorted({f.get("host") for f in rec.get("files") or [] if f.get("host")})
        hv = self.store.host_versions(hosts)
        basis, mixed = {}, {}
        for f in rec.get("files") or []:
            h, p = f.get("host"), str(f.get("product", "")).split("-")[0]
            if not h or not p:
                continue
            r, mx = _pick_version(hv, h, p, str(f.get("instance") or ""))
            if mx:
                mixed.setdefault(p, sorted(set(mixed.get(p, [])) | {f"{h}: " + x for x in mx}))
            elif r:
                b = {"host": h, "instance": r.get("instance") or "", "version": r["version"], "source": r["source"], "at": r["at"], "actor": r["actor"]}
                old = basis.get(p)
                if old and old["version"] != b["version"]:   # 같은 제품을 판이 다른 두 호스트·인스턴스에서 모았다 — 한 판으로 다시 보지 않는다
                    mixed.setdefault(p, sorted({f"{old['host']}{('#' + old['instance']) if old['instance'] else ''}={old['version']}",
                                                f"{h}{('#' + b['instance']) if b['instance'] else ''}={b['version']}"}))
                else:
                    basis.setdefault(p, b)
        for p in mixed:
            basis.pop(p, None)
        items = []
        for c in rec.get("checklist") or []:
            pr = (c.get("product") or "").split("-")[0]
            b = basis.get(pr)
            cmds = []
            for x in c.get("cmds") or []:
                fit = KQ.version_fit(x.get("tail", ""), pr, b["version"]) if b else x.get("fit", "")
                cmds.append({"hash": x.get("hash"), "fit": fit, "copy": bool(x.get("safe")) and fit != "어긋남",
                             "basis": (("제출 출력 확인" if b["source"] == "evidence" else "담당자 지정") if b else
                                       "판 혼재 가능(인스턴스 미지정)" if pr in mixed else "추정")})
            items.append({"rule_id": c.get("rule_id"), "cmds": cmds})
        if basis or mixed:
            self.store.add_reeval(incident_id, {**basis, **({"_mixed": mixed} if mixed else {})}, actor={"login": getattr(self.actor, "login", "")})
        note = "원래 분석 결과는 그대로입니다 — 이 화면에만 지금 기록된 판 기준으로 다시 계산했습니다."
        if mixed:
            note += (" 판이 다른 기록이 함께 있어 다시 보지 않은 제품: " + "; ".join(f"{p}({', '.join(v)})" for p, v in mixed.items()) +
                     " — 분석할 때 호스트명#인스턴스로 넣거나 인스턴스별로 판을 지정하십시오.")
        return {"basis": basis, "mixed": mixed, "items": items, "note": note}

    _ATT_CACHE: dict = {}

    def kb_attention(self):
        """7차 아이디어 12: 확인이 필요한 지식 — 판정별로 '왜 확인이 필요한지'를 따로 표시한다(위험을 한 점수로 합치지 않는다 — GPT 60차).
        지식 파일 지문이 같으면 다시 계산하지 않는다."""
        from . import kb_audit, knowledge_quality as KQ
        base = Path(self._base)
        try:
            fp = KQ.fingerprint(KQ.file_hashes(base))
            hit = self._ATT_CACHE.get(str(base))
            if not hit or hit[0] != fp:
                a = kb_audit.audit(base)
                low = {(x["key"], x["product"]) for x in a["low_fit"]}
                ver = KQ.load_verification(base / "errorcodes")
                rows = []
                for x in a["rows"]:
                    flags = []
                    if x["ambiguous"]:
                        flags.append("매칭 모호")
                    if (x["key"], x["product"]) in low:
                        flags.append("제목 핵심어 0")
                    if x["unverified"]:
                        flags.append("미확인 포함")
                    ax = KQ.axes(x["key"], ver=ver, product=x["product"])
                    if ax["exec"] == "실패" or ax["syntax"] == "실패":
                        flags.append("문법·실행 실패")
                    elif ax["exec"] == "시험 환경 없음":
                        flags.append("시험 환경 없음")
                    rows.append({**x, "flags": flags, "cross": ax["cross"]})
                hit = (fp, rows, len(a["ghosts"]))
                self._ATT_CACHE[str(base)] = hit
            rows = [dict(r) for r in hit[1]]
            fb = self.store.feedback_summary()
            for r in rows:
                rid = r["key"].split(":", 1)[-1] if ":" in r["key"] else r["key"]
                fails = sum(v.get("fail", 0) + v.get("version", 0) for k in (r["key"], rid) for v in (fb.get(k) or {}).values())
                if fails:
                    r["flags"] = r["flags"] + [f"현장 안 됨·판 다름 {fails}"]
            rows = [r for r in rows if r["flags"]]
            counts: dict = {}
            for r in rows:
                for f in r["flags"]:
                    counts[f.split(" ")[0] if f.startswith("현장") else f] = counts.get(f.split(" ")[0] if f.startswith("현장") else f, 0) + 1
            return {"rows": rows[:3000], "total": len(rows), "counts": counts, "ghosts": hit[2], "fingerprint": hit[0]}
        except Exception as e:   # noqa: BLE001 — 표를 못 만들어도 분석은 그대로
            return {"error": f"확인 목록을 만들지 못했습니다: {e}"}

    def postmortem_proposals(self):
        try:
            allr = self.store.postmortem_proposals(include_near=True)
            return {"rows": [x for x in allr if not x.get("near")], "near": [x for x in allr if x.get("near")],
                    "note": "개선 제안 초안입니다 — 룰은 자동으로 바뀌지 않습니다. 확정 빗나감이 서로 다른 장애 2건 이상인 판정만. "
                            "'같은 장애로 묶인 건'은 자동 식별(시각·호스트·파일)이 한 장애로 본 것 — 실제로 다르면 관리자가 나눕니다."}
        except Exception as e:
            return {"error": str(e)}

    def postmortem_review(self):
        try:
            return {"rows": self.store.postmortem_review()}
        except Exception as e:
            return {"error": str(e)}

    def pilot_metrics(self, days: int = 30):
        """22차: 시범 운영 지표 — 제품이 실제로 남긴 기록만 센다(가정값 없음). 모아 센 숫자만 내고 호스트 · 장비 이름 · 원문은 내지 않는다.
        사람의 보고서 작성 시간 · 2차 이관 정확도는 제품이 재지 못하므로 '수기로 잴 것'으로 따로 적는다(재지 않은 값을 만들지 않는다)."""
        import statistics as _st
        from datetime import datetime as _dt, timedelta as _td
        from .demo_data import PREFIX as _DEMO
        try:
            days = max(1, min(int(days or 30), 365))
        except (TypeError, ValueError):
            days = 30
        since = (_dt.now() - _td(days=days)).strftime("%Y-%m-%d")
        inc, acts, pms = self.store.pilot_rows(since)
        recs = []
        for r in inc:
            if str(r.get("id", "")).startswith(_DEMO):
                continue
            d = r.get("data")
            if isinstance(d, str):
                try:
                    d = json.loads(d)
                except ValueError:
                    d = {}
            recs.append((str(r["id"]), storage._iso_to_epoch(str(r.get("analyzed_at") or "").replace("T", " ")), d or {}))
        ids = {i for i, _, _ in recs}
        mine = [a for a in acts if str(a.get("incident_id")) in ids]
        med = lambda xs: (round(_st.median(xs), 1) if xs else None)   # noqa: E731
        secs = [float(d["elapsed_sec"]) for _, _, d in recs if isinstance(d.get("elapsed_sec"), (int, float))]
        first_act = []
        for i, t0, _ in recs:
            ts = [float(a["at"]) for a in mine if str(a["incident_id"]) == i and a.get("at")]
            if ts and t0:
                first_act.append(max(0.0, (min(ts) - t0) / 60.0))
        mins = [int(a["minutes"]) for a in mine if a.get("minutes") is not None]
        res = {}
        for a in mine:
            res[a.get("result") or "pending"] = res.get(a.get("result") or "pending", 0) + 1
        recur = recur_past = learned = same_log = 0
        # GPT 171: 이름만 같으면 날짜가 다른 별도 장애일 수 있다 — 파일 이름 + 파일별 이벤트 수를 함께 지문으로(분석 경로는 건드리지 않음).
        # 이름만 바꾼 같은 로그는 못 가린다 — 주석에 적는다
        files = lambda d: tuple(sorted((str((f or {}).get("name") or (f or {}).get("path") or f), int((f or {}).get("events") or 0) if isinstance(f, dict) else 0)   # noqa: E731
                                       for f in (d.get("files") or [])))
        for i, t0, d in recs:
            sig = storage.signature_of(d)
            # GPT 170: 같은 증상 서명은 같은 원인을 증명하지 않는다 — '유사 증상 재등장'. 같은 로그를 다시 분석한 것은 빼고 따로 센다
            prev = [d2 for _, t2, d2 in recs if t2 < t0 and sig and storage.signature_of(d2) == sig]
            if prev and files(d) and any(files(d2) == files(d) for d2 in prev):
                same_log += 1
                continue
            if prev:
                recur += 1
                # 그 분석 **시점 이전에** 적힌 조치만(나중에 적은 조치가 '그때 있던 것'처럼 세지지 않게)
                if any(str(a.get("signature") or "") == sig and str(a.get("incident_id")) != i and float(a.get("at") or 0) < (t0 or 0) for a in acts):
                    recur_past += 1
        for i, t0, d in recs:
            rids = [str((d.get("first") or {}).get("rule_id") or "")] + [str(x.get("rule_id") or "") for x in (d.get("timeline") or []) + (d.get("checklist") or [])]
            if any(x.startswith("LRN-") for x in rids):
                learned += 1
        ok = {"yes": 0, "partial": 0, "no": 0}
        miss_confirmed = 0
        for p in pms:
            if str(p.get("incident_id")) not in ids:
                continue
            k = str(p.get("verdict_ok") or "")
            if k in ok:
                ok[k] += 1
            if k == "no" and p.get("certainty") == "confirmed":
                miss_confirmed += 1
        return {
            "days": days, "since": since, "analyses": len(recs),
            "engine_sec_median": med(secs), "engine_sec_n": len(secs),
            "first_action_min_median": med(first_act), "first_action_n": len(first_act),
            "action_n": len(mine), "action_min_median": med(mins), "action_min_sum": sum(mins), "action_min_n": len(mins),
            "action_results": res,
            "recur": recur, "recur_with_past": recur_past, "same_log_reanalysis": same_log, "learned_hits": learned,
            "verdict": ok, "verdict_n": sum(ok.values()), "miss_confirmed": miss_confirmed,
            "unreviewed": len(recs) - sum(ok.values()),
            "review_rate": (round(100.0 * sum(ok.values()) / len(recs), 1) if recs else None),
            "manual": ["사람이 보고서를 쓰는 데 걸린 시간 — 제품은 보고서를 만든 시각만 알 수 있어 시범 기간에 수기로 잽니다",
                       "2차 이관이 맞았는지 — 이관 결과를 남기는 칸이 없어 시범 기간에 수기로 잽니다",
                       "도입 전 평균 작업 시간 — 비교 기준이라 시범 시작 전에 따로 잽니다"],
            "notes": ["활동 지표입니다 — 제품 사용 · 기록 · 검토 현황이지 업무 시간 절감의 증거가 아닙니다(절감은 도입 전후 실측으로 따로)",
                      "'첫 조치 기록까지'는 분석 완료부터 첫 조치를 기록한 시각까지 — 실제 대응 착수 · 복구 시간(MTTR)이 아닙니다",
                      "유사 증상 재등장은 같은 증상 서명이 앞서 있던 분석 — 같은 원인이라는 뜻이 아니며, 같은 로그(파일 이름 · 이벤트 수가 같음)를 다시 분석한 것은 빼고 따로 셉니다(이름만 바꾼 같은 로그는 못 가림)",
                      "사후 검토 결과는 사후 원인을 기록한 건만 — 미검토 건과 검토율을 함께 봅니다"],
        }

    def effect_report(self, days: int = 30):
        from .effect import report
        return report(self.automation, days)

    def effect_set(self, values: dict):
        from .effect import set_assumptions
        try:
            return {"ok": True, "assumptions": set_assumptions(self.automation, values or {})}
        except ValueError as e:
            return {"error": str(e)}

    # ── 시연 자료 — 빈 화면으로 보여 주지 않기 위한 표본(관리자만) ──
    def demo_status(self):
        from .demo_data import status
        return status(self)

    def demo_seed(self, force: bool = False):
        from .demo_data import seed
        return seed(self, force=bool(force))

    def demo_clear(self):
        from .demo_data import clear
        r = clear(self)
        self._mark_history(force=True)   # 10차: 앱 안에서 지운 것 — 이력 감소 경고 기준을 맞춘다
        return r

    def reports_dir(self):
        """장애 보고서·분석요약이 놓이는 곳.

        [예약·자동화 → 저장 경로]에서 정한 산출물 경로를 그대로 따른다 — 정기 보고서는 거기,
        장애 보고서는 설치 폴더로 갈라지면 담당자가 두 곳을 뒤져야 한다.
        경로가 비었거나 쓸 수 없으면 예전처럼 <설치경로>/reports 를 쓴다.
        """
        try:
            d = Path(self.automation.output_dir())
            d.mkdir(parents=True, exist_ok=True)
            return d
        except Exception:
            return self._base / "reports"

    def report_dirs(self):
        """내려받기·목록에서 볼 곳 — 지금 경로 + 예전 위치(이미 만들어 둔 보고서 보존)."""
        out, seen = [], set()
        for d in (self.reports_dir(), self._base / "reports"):
            rp = Path(d)
            if str(rp) not in seen:
                seen.add(str(rp))
                out.append(rp)
        return out

    def generate_report(self, incident_id: str = "", values: dict | None = None):
        r = super().generate_report(incident_id, values)
        if isinstance(r, dict) and not r.get("error"):
            r["downloads"] = {k: f"/reports/{Path(v).name}" for k, v in r.items()
                              if isinstance(v, str) and Path(v).exists()}
            r["download_list"] = [{"name": Path(p).name, "url": f"/reports/{urllib.parse.quote(Path(p).name)}"}
                                  for p in (r.get("hwpx_all") or []) + ([r["html"]] if r.get("html") else [])
                                  + ([r["todo_file"]] if r.get("todo_file") else [])
                                  if Path(p).exists()]
        return r

    def learn_report_style(self, path: str = ""):
        """서버형: 업로드 폴더 또는 --allow-dir 아래 경로만 허용(서버 파일 시스템 임의 접근 방지)."""
        p = Path(path or "")
        if not path or not p.exists() or not self._allowed(p):
            return {"error": "허용되지 않은 경로 — 업로드 폴더(uploads) 또는 --allow-dir 아래의 zip/폴더만 가능합니다"}
        return super().learn_report_style(path)


PROXY_HEADER = "X-LogTriage-Proxy"


def proxy_secret() -> str:
    """정식 설치(install.sh)가 nginx 설정과 server.env 에 함께 적는 앞단 비밀 — 32자 미만이면 없는 것으로 본다."""
    s = os.environ.get("LOGTRIAGE_PROXY_SECRET", "").strip()
    return s if len(s) >= 32 else ""


def forwarded_client(sock_ip: str, headers) -> str:
    """우리 nginx 를 거친 요청이면 nginx 가 적어 준 실제 접속자 주소, 아니면 "" (RHEL 검증 매뉴얼 작성 중, GPT 177).

    믿는 조건 셋: 소켓 피어가 루프백 · 설치 때 nginx 와 나눠 가진 비밀 머리글이 맞음 · X-Real-IP 가 IP 꼴.
    - X-Forwarded-For 는 출처로 쓰지 않는다 — nginx 의 $proxy_add_x_forwarded_for 는 접속자가 보낸 값 **뒤에** 붙이므로
      첫 값은 접속자가 마음대로 적는다(그 값을 믿어 로그인 시도 제한 우회 · 다른 감시 대상 IP 행세가 가능했다).
    - 비밀을 보지 않으면 같은 서버의 다른 계정이 앱 포트(127.0.0.1)에 직접 붙어 X-Real-IP 를 꾸며 낼 수 있다.
      비밀은 root 만 읽는 nginx 설정과 root · 서비스 그룹만 읽는 server.env 에만 있다."""
    sec = proxy_secret()
    if not sec or sock_ip not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        return ""
    if not hmac.compare_digest(str(headers.get(PROXY_HEADER) or "").encode(), sec.encode()):
        return ""
    try:
        return str(ipaddress.ip_address(str(headers.get("X-Real-IP") or "").strip()))
    except ValueError:
        return ""


class Handler(BaseHTTPRequestHandler):
    # 연결 하나가 스레드 하나를 쓴다. 본문을 반쪽만 보내고 연결을 끊지 않으면(Content-Length
    # 는 10000 인데 5바이트만 보내는 식) 읽기가 **영원히** 기다려 그 스레드가 묶인다. 몇 번만
    # 하면 서버가 멈춘다(GPT 23차). 느린 사내망에서도 넉넉하되 유한한 시간을 둔다.
    timeout = 60
    server_version = "LogTriage"          # 제품·언어 버전은 응답 헤더에 싣지 않는다(정보 노출)
    sys_version = ""
    api: ServerApi
    password: str | None
    desktop: bool = False  # 데스크톱 exe 내장 서버 모드(네이티브 대화상자; 창은 부트스트랩 토큰으로 세션, 그 외는 비밀번호)
    # 이 PC 전용 창 모드(2026-10-13 마스터 결정 "이 PC 전용이면 로그인 없이"): 창이 127.0.0.1 에서만 열리고 서버 비밀번호가
    # 없을 때. 계정 로그인·첫 계정 만들기를 건너뛰고 **창만 아는 부트스트랩 토큰**으로 세션을 받는다 — 같은 PC 의
    # 다른 프로그램·사용자는 루프백이어도 들어오지 못한다. 다른 PC 가 붙을 수 있는 모드(LAN·서버)는 계정 그대로.
    local_only: bool = False
    boot_token: str | None = None
    _sessions: set[str] = set()

    # ── 유틸 ──
    def _json(self, obj, status=HTTPStatus.OK):
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    _cc_sent = False

    def send_header(self, keyword, value):
        if keyword.lower() == "cache-control":
            self._cc_sent = True       # 이 응답은 제 캐시 지시를 스스로 적었다
        super().send_header(keyword, value)

    def end_headers(self):
        """판 지문은 **모든 응답에 예외 없이** 싣는다.

        전에는 _json·_html·정적 파일 세 자리에서 각각 붙였다. 그래서 그 셋을 지나지 않는
        응답에는 빠졌다 — 지원하지 않는 메서드에 바닥 클래스가 스스로 내보내는 501 이
        그랬다(재어 보고 알았다, GPT 지적). 지금 화면은 그 경로로 요청하지 않지만, 응답
        경로마다 따로 붙이는 구조 자체가 빠뜨릴 자리를 계속 만든다. 나가는 문은 여기
        하나뿐이므로 여기서 붙인다.
        """
        self.send_header("X-LogTriage-Build", buildid.current())
        # 캐시 지시를 스스로 적지 않은 응답에는 여기서 붙인다. 바닥 클래스가 내보내는
        # 501 이 그랬는데, **501 은 기본적으로 캐시해도 되는 응답**이라 앞단 프록시가
        # 담아 둘 수 있다(같은 주소·메서드에 계속 501 을 돌려주는 자리가 생긴다).
        # 화면·API 처럼 제 지시를 가진 응답은 그 값을 그대로 쓴다(더 촘촘하다).
        if not self._cc_sent:
            super().send_header("Cache-Control", "no-store")
        self._cc_sent = False          # 한 연결에서 다음 응답을 위해 되돌린다
        super().end_headers()

    def handle(self):
        self.connection.settimeout(30)
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True  # Browser navigation may cancel an in-flight response.

    def _body(self, length: int) -> bytes:
        """요청 본문을 **한 번만** 읽는다.

        두 번 읽으면 두 번째 읽기가 오지 않을 바이트를 기다려 **응답 없이 멈춘다.** 거절하는
        자리(_reject_json)가 본문을 비우려다 그 일을 겪었다 — 초기 설정 코드를 틀리게 적은
        사람이 오류 화면 대신 멈춘 창을 봤다.
        """
        if getattr(self, "_body_done", False):
            return b""
        self._body_done = True
        return self.rfile.read(length) if length else b""

    def _reject_json(self, value, status):
        # Closing TCP with an unread small POST body can discard the 401/403 response on Windows.
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = 0
        if self.command in ('POST', 'PUT') and 0 < length <= 32768:
            self._body(length)          # 이미 읽었으면 다시 읽지 않는다(멈춤 방지)
        self.close_connection = True
        return self._json(value, status)

    # 화면 응답 공통 보안 헤더 — 취약점 진단에서 늘 확인하는 항목(2026-09-22).
    #   2026-10-15 아이디어 2: 대본은 'unsafe-inline' 없이 — 화면마다 1회용 nonce 를 붙인 <script> 만 돈다.
    #   인라인 이벤트(onclick=…)는 모두 data-click + 위임으로 바꿨고, 화면에 끼어든 <script>·onerror= 는 실행되지 않는다.
    #   스타일은 style= 속성이 많아 'unsafe-inline' 을 남긴다(스크립트 실행 경로가 아니다).
    #   3차 아이디어 1: <style> '요소'는 nonce 가 있어야만(style-src-elem) — 끼워 넣은 <style>(@import·선택자로 값 빼내기)을 막는다.
    #   style= '속성'만 'unsafe-inline'(style-src-attr). CSP3 를 모르는 옛 브라우저는 style-src 로 예전처럼 동작.
    _CSP = ("default-src 'self'; script-src 'self'%NONCE%; style-src 'self' 'unsafe-inline'; style-src-elem 'self'%NONCE%; "
            "style-src-attr 'unsafe-inline'; require-trusted-types-for 'script'; trusted-types default; "
            "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' blob:; media-src 'none'; "
            "object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def _sec_headers(self, nonce: str | None = None):
        self.send_header("Content-Security-Policy", self._CSP.replace("%NONCE%", f" 'nonce-{nonce}'" if nonce else ""))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        # HSTS 는 '실제로 암호화된 연결' 에서만 — 평문에 걸면 브라우저가 그 주소를 HTTPS 로 고정해
        # HTTP 로 다시 못 들어간다(현재 평문 허용 정책과 어긋남).
        xfp = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if getattr(self.server, "tls", False) or (xfp == "https" and self._loopback_peer()):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    # 화면마다 **그 화면을 만든 판의 지문**을 심는다.
    #
    # 판을 올려도 이미 열려 있는 탭은 죽지 않는다 — 캐시 문제가 아니라, 옛 코드가 메모리에서
    # 그대로 돌면서 새 서버를 상대한다. 상황실 벽화면처럼 며칠을 열어 두는 자리가 특히 그렇다.
    # 옛 코드를 지우려면 먼저 '달라졌다' 를 알아야 하고, 화면이 스스로 그것을 알 근거는
    # **자기를 만든 판의 지문**뿐이다. 첫 통신 때 받아 적으면 늦다(판 올리기와 겹친 몇백
    # 밀리초 사이에 새 지문을 자기 것으로 적어 버려, 옛 코드인데 최신인 줄 안다).
    _build_meta_cache: str | None = None

    @classmethod
    def _build_meta(cls) -> str:
        if cls._build_meta_cache is None:
            cls._build_meta_cache = f'<meta name="lt-build" content="{html_escape(buildid.current())}">'
        return cls._build_meta_cache

    def _html(self, text: str, status=HTTPStatus.OK, extra: dict | None = None):
        if "<head>" in text:
            text = text.replace("<head>", "<head>" + self._build_meta(), 1)
        if "<head>" in text and "<script" in text:   # 3차 아이디어 2: Trusted Types 기본 정책을 다른 대본보다 먼저
            from .links import TT_JS, extra_hosts
            xh = json.dumps(extra_hosts(self.api._base)) if getattr(self, "api", None) else "[]"
            tt = "<script>" + TT_JS + "window.LT_LINK_HOSTS_EXTRA=" + xh + ";</script>"
            # 판 지문(meta lt-build)이 모든 대본보다 앞이어야 한다(옛 코드 차단 원칙) — 정책 대본은 그 바로 뒤
            m = re.search(r'<meta name="lt-build"[^>]*>', text)
            text = (text[:m.end()] + tt + text[m.end():]) if m else text.replace("<head>", "<head>" + tt, 1)
        if "</head>" in text and getattr(self, "native", self.desktop):
            # 창(pywebview)이 문서에 넣던 '본문 글자 선택 끔' <style> 은 nonce 가 없어 이제 막힌다(style-src-elem) —
            # 창 주입은 끄고(text_select=True) 같은 규칙을 우리가 표를 달아 넣는다. 동작은 예전 그대로(데스크톱 창만).
            text = text.replace("</head>", "<style>body{-webkit-user-select:none;user-select:none;cursor:default}</style></head>", 1)
        nonce = None
        if "<script" in text:    # 이 응답의 <script> 에만 1회용 표 — 끼워 넣어진 대본은 표가 없어 돌지 않는다
            nonce = secrets.token_urlsafe(18)
            text = re.sub(r"<script\b", f'<script nonce="{nonce}"', text)
        if "<style" in text:     # 화면의 <style> 요소도 같은 표(3차 아이디어 1)
            nonce = nonce or secrets.token_urlsafe(18)
            text = re.sub(r"<style\b", f'<style nonce="{nonce}"', text)
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # 화면은 **저장하지 않는다.** 전에는 캐시 지시가 하나도 없었다 — 브라우저마다,
        # 앞단 프록시마다 알아서 판단하라는 뜻이고, 그러면 "패치했는데 옛 화면" 을 막을
        # 근거가 없다. 화면 안에는 로그인한 사람의 이름·권한과 폼 토큰이 들어 있으므로
        # 공용 PC 디스크에 남기지 않는 것이 겸하여 옳다. 값은 다시 받는다(사내망 기준
        # 가장 큰 화면이 0.7MB, LAN 에서 수십 밀리초) — 느려지는 만큼은 감수한다.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")          # 옛 프록시용
        self.send_header("Expires", "0")
        self._sec_headers(nonce)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _same_origin(self) -> bool:
        """상태 변경 요청(POST/PUT)의 Origin 이 있으면 요청 Host 와 일치해야 한다(CSRF 심층 방어)."""
        # 브라우저가 스스로 붙이는 표시 — 위조할 수 없다. 비브라우저(에이전트)는 안 붙이므로
        # '있을 때만' 본다. Origin 이 빠진 교차 출처 폼 전송이 이 검사에서 걸린다(GPT 10차).
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site and site not in ("same-origin", "none"):
            return False
        origin = self.headers.get("Origin", "")
        if not origin or origin == "null":
            return True
        return urllib.parse.urlsplit(origin).netloc.lower() == (self.headers.get("Host") or "").lower()

    def _https_ok(self) -> bool:
        """이 요청이 암호화 구간으로 들어왔는가 — 서버가 직접 TLS 로 받았거나, 같은 PC 의 TLS 앞단(nginx)이 붙인 표시."""
        if getattr(self.server, "tls", False):
            return True
        xfp = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if xfp == "https":
            # 앞단 표시는 같은 PC 의 프록시만 믿는다(헤더 위조 방지). 정식 설치처럼 앞단 비밀이 있으면 그 비밀까지 맞아야 한다 —
            # 같은 서버의 다른 계정이 앱 포트에 직접 'https' 라고 적어 보내는 것을 막는다(GPT 178)
            if not self._loopback_peer():
                return False
            sec = proxy_secret()
            return not sec or hmac.compare_digest(str(self.headers.get(PROXY_HEADER) or "").encode(), sec.encode())
        return self._loopback_peer() and xfp == ""

    def _plaintext_lan(self) -> bool:
        """22차: 다른 PC 에서 암호화 없이(HTTP) 들어온 접속인가 — 비밀번호 · 세션 쿠키가 망에 평문으로 흐른다.
        같은 PC(루프백 직접)는 망을 지나지 않으므로 아니다. 앞단(nginx)이 http 라고 알려 준 요청은 평문이다."""
        if self._https_ok():
            return False
        xfp = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        return not (self._loopback_peer() and xfp == "")

    PLAINTEXT_WARN = ("이 접속은 암호화되지 않았습니다(HTTP) — 로그인 비밀번호와 세션이 사내망에 그대로 흐릅니다. "
                      "관리자: HTTPS 를 켜고(서버 conf/tls.json 또는 설치 install.sh --tls) 계정 설정 require_https 를 true 로 두면 평문 접속을 막습니다.")

    def _private_peer(self) -> bool:
        """사내망·VPN 처럼 내부 주소에서 온 접속인지 — 인터넷 구간과 구분한다(2026-09-22)."""
        try:
            ip = ipaddress.ip_address(self.client_address[0].replace("::ffff:", ""))
        except ValueError:
            return False
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)

    def _need_https(self) -> bool:
        """설정 require_https: true(항상) · false(쓰지 않음) · "auto"(기본: 인터넷 구간만 요구, 사내망·VPN·같은 PC 는 평문 허용)."""
        ac = self.api.auth_conf
        if not ac or ac["mode"] not in ("portal", "local"):
            return False
        want = ac.get("require_https", "auto")
        if want is False:
            return False
        xfp = (self.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()
        if xfp and xfp != "https":
            # 앞단(nginx)이 '바깥 구간은 평문이었다'고 알려 준 요청. 전에는 언제나 거절해 --tls 없는 정식 설치가 로그인 화면부터
            # 모두 403 이었다(RHEL 검증 매뉴얼 작성 중 발견, GPT 177). auto 면 run.sh 직접 접속과 같은 규칙으로 실제 접속자 주소를 본다.
            # 그 주소를 믿을 수 없거나(우리 nginx 가 아님) 앞단이 둘 이상이면(X-Forwarded-For 가 접속자 한 칸이 아님 — 바깥
            # 부하분산기를 거친 인터넷 접속일 수 있다) 거절한다
            if want is True:
                return True
            real = forwarded_client(self.client_address[0], self.headers)
            hops = []
            for h in (self.headers.get("X-Forwarded-For") or "").split(","):
                try:
                    hops.append(str(ipaddress.ip_address(h.strip())))
                except ValueError:
                    hops.append("?")
            if not real or hops != [real]:
                return True
            ip = ipaddress.ip_address(real)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        if want is True:
            return True
        return not self._private_peer()

    def _loopback_peer(self) -> bool:
        return self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _begin(self) -> bool:
        """요청 시작 공통: 피어 플래그 기록 + 데스크톱 모드 Host 검증(DNS 리바인딩 방어: Host 는 IP 리터럴 또는 localhost 만). False 면 403 을 보냈다."""
        _req.loopback = self._loopback_peer()
        self._u_done, self._u, self._auth_msg, self._mc_cache = False, None, "", None
        ac = self.api.auth_conf
        if self._need_https() and not self._https_ok()                 and urllib.parse.urlsplit(self.path).path not in ("/api/nms/metrics", "/healthz"):   # 에이전트 수치 전송(쓰기 전용 토큰)·상태 확인은 제외
            self._reject_json({"error": "암호화 연결(HTTPS)로만 접속할 수 있습니다 — https:// 주소로 접속하거나 VPN·사내망을 통해 접속하십시오"},
                              HTTPStatus.FORBIDDEN)
            return False
        if self.desktop:
            host = (self.headers.get("Host") or "").strip().lower()
            h = host.split("]")[0] + "]" if host.startswith("[") else host.rsplit(":", 1)[0]
            if not (h in ("localhost", "[::1]") or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h) or re.fullmatch(r"\[[0-9a-f:.]+\]", h)):
                self._json({"error": "허용되지 않는 Host 헤더"}, HTTPStatus.FORBIDDEN); return False
        return True

    def _bootstrap(self, u):
        """데스크톱 창 전용: 프로세스만 아는 부트스트랩 토큰(/auth/bootstrap?t=)으로 세션 쿠키 발급 — 같은 PC 의 다른 사용자·프로세스는 루프백이어도 로그인 필요"""
        tok_in = (urllib.parse.parse_qs(u.query).get("t") or [""])[0]
        if self._local_login():   # 회사 이메일 계정을 쓰면 창에서도 로그인 화면을 거친다
            return self._html("", HTTPStatus.FOUND, {"Location": "/setup" if self._needs_setup() else "/login"})
        if self.boot_token and self._loopback_peer() and tok_in.isascii() and hmac.compare_digest(tok_in, self.boot_token):
            if self.local_only:
                type(self).boot_token = None   # 이 PC 전용 창: 한 번 쓰면 끝(기록·캐시에 남은 주소로 다시 못 들어온다)
            tok = secrets.token_hex(16); self._sessions.add(tok)
            return self._html("", HTTPStatus.FOUND, {"Location": "/", "Set-Cookie": f"lt_session={tok}; Path=/; HttpOnly; SameSite=Strict"})
            # 캐시 금지(no-store)·Referrer-Policy no-referrer 는 모든 화면 응답에 이미 붙는다(_html) — 시험이 확인
        return self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)

    # ── 인증·권한(r4): 통합 계정(auth.json) 또는 기존 단일 비밀번호 ──
    _fail: dict = {}        # IP → 최근 로그인 실패 시각(5분 10회 초과 차단)
    _hdr_cache: dict = {}   # header SSO: 로그인 → (시각, 사용자) 60초 캐시

    def _ip(self) -> str:
        """접속자 주소 — 로그인 시도 제한 · 감사 · 에이전트 출발지에 쓴다. 우리 nginx 가 적어 준 값만 믿고, 아니면 소켓 주소."""
        return forwarded_client(self.client_address[0], self.headers) or self.client_address[0]

    def _cookie(self, name: str) -> str:
        m = re.search(r"(?:^|;\s*)" + name + r"=([^;\s]+)", self.headers.get("Cookie", ""))
        return m.group(1) if m else ""

    def _portal(self) -> bool:
        if self.local_only:
            return False
        c = self.api.auth_conf
        return bool(c and c["mode"] == "portal")

    def _needs_setup(self) -> bool:
        """이메일 로그인인데 계정이 하나도 없는 상태 — 첫 관리자 계정을 만드는 화면으로 보낸다(2026-09-22).

        기동 뒤에 명령줄로 계정을 만들었을 수도 있으므로, 화면을 열기 전에 DB 를 한 번 더 확인하고 닫는다."""
        if not (self._local_login() and self.api.setup_token):
            return False
        if self.api.accounts.count():
            self.api.setup_close()
            return False
        return True

    def _proxied(self) -> bool:
        """앞단(프록시·부하분산기)을 거쳐 온 요청인지 — 그러면 접속 주소는 앞단의 것이라 자리를 판단하는 근거가 못 된다."""
        return any(self.headers.get(h) for h in ("X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP", "Forwarded"))

    def _setup_ok(self, tok: str = "") -> bool:
        """첫 계정을 만들 수 있는 자리인지 — **웹으로는 언제나 1회용 코드**를 받는다(2026-10-02).

        전에는 접속 자리로 갈랐다(setup_scope: loopback·private·token). 같은 PC 에 리버스
        프록시가 있으면 밖에서 온 사람도 127.0.0.1 로 보이므로 그 판단이 서지 않는다 —
        기본값만 고치고 옛 값을 그대로 두면 그 설정이 적힌 설치는 뚫린 채 남는다.
        setup_scope 는 이제 아무것도 열지 않고, 옛 값이 있으면 기동할 때 알린다.
        코드 없이 만드는 길은 서버 콘솔에 있다: python -m logtriage.accounts add --role admin."""
        # **웹으로 첫 계정을 만드는 길에는 예외가 없다**(2026-10-02, GPT 23차).
        #
        # 전에는 접속 자리로 갈랐다(루프백·사내망은 코드 없이). 같은 PC 에 리버스 프록시가
        # 있으면 밖에서 온 사람도 127.0.0.1 로 보이므로 그 판단이 서지 않는다. 기본값만
        # 고치고 옛 값(loopback·private)을 그대로 두면 **그 설정이 적힌 설치는 뚫린 채 남는다**
        # — 지금 현장 설치가 그렇다. 그래서 설정과 무관하게 언제나 코드를 받는다.
        # 서버 콘솔에서 코드 없이 만드는 길은 그대로 있다(python -m logtriage.accounts add).
        if not tok:
            tok = (urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("t") or [""])[0]
        # 코드 칸에 한글을 붙여 넣으면 compare_digest 가 TypeError 를 낸다 — 거절할 자리에서
        # 서버가 터지면 안 된다. ASCII 가 아닌 것은 애초에 우리 코드가 아니다.
        if not tok or not tok.isascii() or len(tok) > 64:
            return False
        # 판정만 한다 — 틀린 코드를 세는 일은 요청을 다루는 자리에서 한다(_failed).
        return bool(self.api.setup_token and hmac.compare_digest(tok, self.api.setup_token))

    _REAUTH_HITS: dict = {}
    REAUTH_MAX, REAUTH_WINDOW = 5, 600.0

    def _reauth(self, password: str) -> tuple:
        """되돌릴 수 없는 관리 작업 전 비밀번호 재입력(7차 아이디어 5 · GPT 60차) → (통과, 방식, 거절 사유).
        방식: email(사내 계정) / shared(공용 비밀번호) / none(로그인 없음·외부 인증 — 앱이 재확인할 수 없어 작업 자체를 막는다).
        GPT 61차: 계정 잠금 정책은 그대로 두되, 남의 관리자 계정을 일부러 잠그는 것을 막게 재인증 시도 자체를 세션 주인·접속지별로 10분 5회로 제한."""
        import time as _t
        who = f"{(getattr(self, '_u', None) or {}).get('login', '')}|{self._ip() if hasattr(self, '_ip') else ''}"
        now = _t.time()
        hits = [x for x in self._REAUTH_HITS.get(who, []) if now - x < self.REAUTH_WINDOW]
        if len(hits) >= self.REAUTH_MAX:
            return False, "limited", "비밀번호 재확인 시도가 너무 많습니다 — 10분 뒤 다시 하십시오"
        hits.append(now)
        self._REAUTH_HITS[who] = hits
        if self._local_login():
            u = self._u or {}
            try:
                self.api.accounts.verify(str(u.get("email") or u.get("login") or ""), password, self._ip())
                return True, "email", ""
            except authmod.AuthError as e:
                return False, "email", str(e)
        if self.password:
            ok_pw = pw_ok(password, self.password) if password else False
            if ok_pw is None:
                return False, "error", "서버가 지금 비밀번호를 확인하지 못했습니다(실패로 세지 않음) — 잠시 뒤 다시 하십시오"
            if ok_pw:
                return True, "shared", ""
            return False, "shared", "비밀번호가 맞지 않습니다"
        return False, "none", "로그인 없는(또는 앱이 비밀번호를 다시 확인할 수 없는) 모드에서는 앱에서 지우지 않습니다 — 격리 폴더는 OS 관리자가 직접 지우십시오"

    def _local_login(self) -> bool:
        """사내 이메일 계정 로그인(mode=local). 이 PC 전용 창 모드에서는 쓰지 않는다(local_only)."""
        if self.local_only:
            return False
        c = self.api.auth_conf
        return bool(c and c["mode"] == "local" and self.api.accounts)

    def _domain(self) -> str:
        return (self.api.accounts.conf["domain"] if self.api.accounts else "solideos.com")

    def _user(self):
        if getattr(self, "_u_done", False):
            return self._u
        self._u_done, self._u = True, None
        m = re.search(r"lt_session=([0-9a-f]{32})", self.headers.get("Cookie", ""))
        conf = self.api.auth_conf
        if self.local_only:   # 이 PC 전용 창: 부트스트랩으로 받은 세션만(루프백이라는 것만으로는 안 된다)
            if m and m.group(1) in self._sessions:
                self._u = dict(LEGACY_USER, login="(이 PC)", name="이 PC 사용자")
            return self._u
        if conf and conf["mode"] == "local":   # 사내 이메일 계정: 로그인 세션만 인정
            self._u = self.api.auth.session_user(self._cookie("lt_sid"), conf["session_idle_min"], conf["session_max_hours"])
        elif conf and conf["mode"] == "portal":   # 통합 로그인 사용 중에는 단일 비밀번호·데스크톱 부트스트랩 세션을 인정하지 않음(r4 검토)
            u = self.api.auth.session_user(self._cookie("lt_sid"), conf["session_idle_min"], conf["session_max_hours"])
            if not u and conf["portal"]["method"] == "header":
                u = self._header_user()
            self._u = u
        elif m and m.group(1) in self._sessions:   # 데스크톱 창(부트스트랩) 또는 기존 단일 비밀번호 세션
            self._u = dict(LEGACY_USER, login="(이 PC)" if self.desktop else "(공용)", name="이 PC 사용자" if self.desktop else "공용 접속")
        elif not self.password and (conf is None or conf["mode"] == "off"):
            # 22차(GPT 166 조건부 P0): 로그인 없는 서버는 '이 PC 안'이라서 허용한 것 — 앞단(nginx)을 거쳐 온 요청은
            # 바깥 사람이므로 사용자로 보지 않는다(앱이 127.0.0.1 에 떠도 nginx 가 LAN 을 받으면 열려 있는 것과 같다)
            if self.desktop or not self._proxied():
                self._u = dict(LEGACY_USER)
        return self._u

    def _header_user(self):
        conf = self.api.auth_conf
        try:
            info = authmod.header_login(conf, self.client_address[0], self.headers)
        except authmod.AuthError as e:
            self._auth_msg = str(e)
            return None
        now = time.time()
        hit = self._hdr_cache.get(info["login"])
        if hit and now - hit < 60:   # 신원(이름·부서·그룹) 동기화만 60초 캐시 — 권한·사이트·중지 여부는 매 요청 DB 에서 읽는다(r4 검토)
            u = self.api.auth.get_user(info["login"])
            return u if u and not u.get("disabled") and u.get("source") != "local" else None
        try:
            u = self.api.auth.portal_user(info["login"], conf, info["name"], info["dept"], "", info["groups"], "header")
        except authmod.AuthError as e:
            self._auth_msg = str(e)
            return None
        if not hit:
            self.api.auth.audit(u["login"], self._ip(), "login", "header")
        self._hdr_cache[info["login"]] = now
        return u

    def _authed(self) -> bool:
        return self._user() is not None

    def _need(self, method: str, path: str) -> str:
        if path.startswith("/api/board/") or path == "/board":
            return "viewer"          # 게시판은 조회 권한도 글·답글을 쓸 수 있다(서로 묻고 답하는 공간)
        if path.startswith("/api/access/") or path == "/access-request":
            return "viewer"          # 막힌 사람이 보내는 요청이다 — 막혀 있다고 요청까지 막으면 뜻이 없다
        if path.startswith(("/api/admin/", "/api/hub/admin/")) or path in ("/admin", "/api/rulepack", "/api/automation/set_outputs",
                                                                       "/api/automation/purge_uploads"):
            return "admin"
        if path in ("/api/nms/agent", "/api/nms/agent_tokens") or path.startswith(("/static/lt-agent", "/api/automation/download")):
            return "operator"   # 에이전트 토큰·백업·산출물 원본이 들어 있음(개별 스크립트에도 토큰이 채워진다)
        if method == "GET":
            return "viewer"
        if path.startswith("/api/") and path[5:] in API_NAMES:
            n = path[5:]
            return "viewer" if n in READ_APIS else ("admin" if n in ADMIN_APIS else "operator")
        return "operator"

    def _local_site(self) -> str:
        hc = self.api.hub_conf
        return hc["site_id"] if hc else "LOCAL"

    def _admin_net_ok(self, path: str) -> bool:
        """관리자 화면·API 를 정해진 대역에서만 — conf/auth.json 의 admin_allow(CIDR 목록). 비우면 제한 없음(2026-09-22)."""
        nets = (self.api.auth_conf or {}).get("admin_allow") or []
        if not nets or not (path.startswith(("/api/admin/", "/api/hub/admin/")) or path == "/admin"):
            return True
        try:
            # 소켓 피어만 쓴다 — X-Forwarded-For 는 앞단 설정에 따라 공격자가 왼쪽 값을 넣을 수 있다
            ip = ipaddress.ip_address(self.client_address[0].replace("::ffff:", ""))
        except ValueError:
            return False
        ok = False
        for n in nets:
            try:
                if ip in ipaddress.ip_network(str(n).strip(), strict=False):
                    ok = True
            except ValueError:      # 설정이 잘못되면 열어 주지 않는다(fail-closed)
                sys.stderr.write("[auth] admin_allow 형식 오류: " + repr(n) + " - 관리자 화면을 막습니다" + chr(10))
                return False
        return ok

    def _asset_ok(self, path: str) -> bool:
        """사이트 자산 현황(자산 관리) — 이 사이트가 자산 조회 사이트로 명시된 담당자만(관리자도 예외 없음)."""
        if path in ("/resources", "/resources/view") or path.startswith("/api/inventory/"):
            return authmod.asset_allowed(self._u, self._local_site())
        if self.command in ("POST", "PUT") and path.startswith("/api/nms/") and path != "/api/nms/metrics":
            return authmod.asset_allowed(self._u, self._local_site())   # 감시 장비(IP) 등록·변경 = 자산 정보 변경
        if path.startswith("/api/automation/download"):
            return authmod.asset_allowed(self._u, self._local_site())   # 점검 결과·보고서에는 장비 IP 목록이 들어 있다
        if path.startswith("/static/lt-agent") or path in ("/api/nms/agent_tokens", "/api/nms/agent", "/api/nms/agent_enroll_state"):   # 19차: /api/nms/agent 는 공용 토큰 원문을 준다
            return authmod.asset_allowed(self._u, self._local_site())   # 에이전트 배포물에는 그 장비의 수집 토큰이 들어간다
        return True

    _MASK_APIS = ("history", "log_incidents", "search_logs", "similar_cases")

    def _incident_of(self, args):
        """첫 인자가 분석 ID 인 API(로그 검색·보고서 생성)에서 그 분석 건을 찾아 준다."""
        if not args or not isinstance(args[0], str) or not args[0].strip():
            return None
        try:
            return self.api.store.get(args[0].strip())
        except Exception:
            return None

    def _same_dept(self, owner: str) -> bool:
        """15차(마스터: '부서가 같으면 누가 로그 분석을 하더라도 공유'): 분석을 등록한 계정과 지금 보는 계정이 같은 부서인가.
        부서는 계정 정보(관리자가 [사용자 · 권한]에서 정함)의 현재 값으로 본다 — 부서를 옮기면 그날부터 새 부서와 공유된다.
        부서가 비어 있으면 공유하지 않는다(빈 값끼리 같다고 보지 않음). 한 요청 안에서는 계정별로 한 번만 찾는다."""
        if not owner:
            return False
        if (self._u or {}).get("dept_self"):
            return False                      # 16차: 스스로 적은 부서(관리자 미확인)는 공유 기준이 아니다
        mine = str((self._u or {}).get("dept") or "").strip()
        if not mine or not getattr(self.api, "auth", None):
            return False
        cache = self.__dict__.setdefault("_dept_cache", {})
        if owner not in cache:
            try:
                u = self.api.auth.get_user(owner) or {}
                cache[owner] = "" if u.get("dept_self") else str(u.get("dept") or "").strip()
            except Exception:   # noqa: BLE001
                cache[owner] = ""
        return bool(cache[owner]) and cache[owner] == mine

    def _can_use_incident(self, iid: str) -> bool:
        """19차: 분석별 보고서 기본 정보는 그 분석을 원본으로 볼 수 있는 사람(등록자·같은 부서)만 읽고 쓴다."""
        if not iid:
            return True
        inc = self._incident_of([iid])
        me = (self._u or {}).get("login", "")
        if not inc:
            return not me          # 지워진 분석의 남은 값은 계정 서버에서 내주지 않는다(PC 단독은 한 사람)
        return self._may_use(privacy.owner_of(inc))

    def _may_use(self, owner: str) -> bool:
        """그 분석으로 보고서·서식 값을 만들 수 있는가 — 등록자 본인·같은 부서(등록자 없는 옛 분석은 예전처럼 허용)."""
        me = (self._u or {}).get("login", "")
        return not (owner and me and owner != me and not self._same_dept(owner))

    _INC_IN_NAME = re.compile(r"(?:INC|DEMO)-\d{8}-\d{6}-\d{6}")

    def _report_file_ok(self, fname: str) -> bool:
        """보고서 파일 이름에 분석 ID 가 있으면 그 분석을 쓸 수 있는 계정(등록자·같은 부서)만 받는다(10-23).
        파일 이름의 분석 ID 는 가려진 이력에도 그대로 보여 추측된다 — 전에는 로그인만 하면 다른 부서 분석의 원본 보고서가 내려갔다.
        분석 ID 가 없는 파일(점검 결과 등)은 예전 그대로."""
        m = self._INC_IN_NAME.search(fname or "")
        return True if not m else self._can_use_incident(m.group(0))

    def _usable_history(self) -> list:
        """'가장 최근 분석' 을 쓰는 곳(분석 ID 없는 보고서·서식 미리보기·서식 예시 값)이 고를 후보 — 이 계정이 쓸 수 있는 분석만, 최신순.
        10-23: 전에는 누구 것이든 맨 앞 분석을 써서, 분석 ID 를 비우면 다른 부서 분석의 원본 보고서가 403 관문을 돌아 나갔다."""
        return [h for h in self.api.history() if self._may_use(privacy.owner_of(h))]

    def _other_owner(self, name: str, args) -> dict | None:
        """다른 계정이 등록한 분석으로 보고서를 만들지 못하게 한다(가려진 값으로 보고서를 쓰면 쓸모가 없다).
        15차: 같은 부서 계정은 함께 쓴다(원본을 보므로 보고서도 만들 수 있다)."""
        if name in ("report_profile", "save_report_profile", "report_profile_get"):
            iid = ""
            if name == "report_profile" and args and isinstance(args[0], str):
                iid = args[0].strip()
            elif name == "save_report_profile" and len(args) > 1 and isinstance(args[1], str):
                iid = args[1].strip()
            elif name == "report_profile_get" and args and isinstance(args[0], str) and args[0].startswith("inc:"):
                iid = args[0][4:].strip()
            if iid and not self._can_use_incident(iid):
                if not self._incident_of([iid]):
                    return {"error": "분석을 찾을 수 없습니다 — 판정 리포트를 다시 열어 주십시오"}
                self._audit("report_profile.denied", iid, "다른 부서 계정이 등록한 분석", ok=False)
                return {"error": "다른 부서 계정이 등록한 분석입니다 — 이 분석의 보고서 기본 정보는 등록한 담당자와 같은 부서만 봅니다"}
            return None
        if name != "generate_report":
            return None
        inc = self._incident_of(args)
        owner = privacy.owner_of(inc or {})
        me = (self._u or {}).get("login", "")
        if inc and owner and me and owner != me and not self._same_dept(owner):
            self._audit("report.denied", args[0] if args else "", "다른 부서 계정이 등록한 분석", ok=False)
            return {"error": "다른 부서 계정이 등록한 분석입니다 — 보고서는 등록한 담당자와 같은 부서만 만들 수 있습니다(장비 정보 보호)"}
        return None

    def _mask_history(self, name: str, res, args=()):
        """분석 이력·로그 검색 결과: 등록한 계정 본인에게만 원본, 다른 계정에게는 IP·호스트명을 ** 로 가린다(2026-09-22)."""
        if name not in self._MASK_APIS or not isinstance(res, (list, dict)):
            return res
        me = (self._u or {}).get("login", "")
        if name == "search_logs" and isinstance(res, dict):
            inc = self._incident_of(args)
            if inc and privacy.owner_of(inc) and (privacy.owner_of(inc) == me or self._same_dept(privacy.owner_of(inc))):
                return res
            return privacy.mask_result(res, privacy.hosts_of(inc) if inc else set())
        if name == "log_incidents" and isinstance(res, list):
            # 이 목록 행에는 이름만 있고 호스트 칸이 없어 행만 보고는 가릴 호스트를 못 찾는다('app01 os_disk' 가 그대로 나갔다, 10-23)
            # → 분석 원본에서 호스트를 뽑아 가린다
            hide = {i for i, r in enumerate(res) if isinstance(r, dict) and not privacy.can_see(privacy.owner_of(r), me, self._same_dept)}
            if not hide:
                return res
            want = {str(res[i].get("id") or "") for i in hide}
            hosts = {h.get("id"): privacy.hosts_of(h) for h in self.api.history() if h.get("id") in want}
            return [privacy.mask_result(r, hosts.get(r.get("id"), set())) if i in hide else r for i, r in enumerate(res)]
        return privacy.mask_for_viewer(res, me, shares=self._same_dept)

    def _mask_home(self, res):
        """홈 '지금 할 일'(open·acting)·'내 최근 분석'(mine) 목록은 저장소 칸을 바로 꺼내 등록자 정보가 없다 —
        분석 건마다 등록자를 찾아 이력과 같은 기준(privacy.can_see)으로 가린다(10-23). 분석을 못 찾으면 가린다."""
        if not isinstance(res, dict):
            return res
        me = (self._u or {}).get("login", "")
        for key in ("open", "acting", "mine"):
            rows = res.get(key)
            if not isinstance(rows, list):
                continue
            out = []
            for r in rows:
                if isinstance(r, dict):
                    inc = self._incident_of([str(r.get("id") or "")])
                    if not privacy.can_see(privacy.owner_of(inc or {}), me, self._same_dept):
                        r = privacy.mask_result(r, privacy.hosts_of(inc) if inc else set())
                out.append(r)
            res[key] = out
        return res

    def _mask_assets(self, data):
        """자산 권한이 없는 사용자에게는 감시 장비 주소(IP)·포트를 가린다(화면 숨김이 아니라 응답 단계에서).
        16차(현장 '포트 정보가 보이면 보안 취약'): 어느 포트로 무엇이 열려 있는지도 주소만큼 민감하다 → port·snmp_port 도 뺀다."""
        if authmod.asset_allowed(self._u, self._local_site()):
            return data
        def walk(v):
            if isinstance(v, dict):
                return {k: ("(자산 권한 필요)" if k in ("address", "snmp_community") and isinstance(x, str) and x else
                            None if k in ("port", "snmp_port") and isinstance(x, int) else walk(x)) for k, x in v.items()}
            if isinstance(v, list):
                return [walk(x) for x in v]
            return v
        return walk(data)

    def _site_ok(self, path: str) -> bool:
        hc = self.api.hub_conf
        if not hc or path.startswith(("/hub", "/api/hub/", "/api/me", "/admin", "/api/admin/", "/static/", "/logout")):
            return True
        return authmod.site_allowed(self._u, hc["site_id"])

    _PW_FREE = ("/password", "/logout", "/api/me", "/login", "/setup", "/recover", "/join", "/healthz", "/static/")

    def _must_change(self) -> bool:
        """임시 비밀번호·기간 만료 상태면 비밀번호 변경 화면 밖으로 나가지 못하게 한다."""
        u = self._u or {}
        if not self._local_login() or u.get("source") != "email":
            return False
        if getattr(self, "_mc_cache", None) is None:
            acc = next((a for a in [self.api.accounts.list_one(u["login"])] if a), None)
            self._mc_cache = bool(acc and (acc["must_change"] or (acc["expires_in"] is not None and acc["expires_in"] <= 0)))
        return self._mc_cache

    def _guard(self, method: str, path: str) -> bool:
        """True = 거절 응답을 이미 보냄. 로그인·권한·사이트 범위를 한곳에서 판단한다."""
        if self._needs_setup():
            if path.startswith("/api/") or method != "GET":
                self._reject_json({"error": "아직 계정이 없습니다 — 먼저 관리자 계정을 만드십시오(/setup)"}, HTTPStatus.UNAUTHORIZED)
            else:
                self._html("", HTTPStatus.FOUND, {"Location": "/setup"})
            return True
        u = self._user()
        if u is None:
            kicked = self._local_login() and self.api.auth.was_kicked(self._cookie("lt_sid"))
            if path.startswith("/api/") or method != "GET":
                self._reject_json({"error": "다른 곳에서 같은 계정으로 로그인해 이 접속은 종료되었습니다" if kicked else "로그인이 필요합니다"},
                                  HTTPStatus.UNAUTHORIZED)
            else:
                self._html("", HTTPStatus.FOUND, {"Location": "/login?kicked=1" if kicked else "/login"})
            return True
        if self._must_change() and not path.startswith(self._PW_FREE):
            if path.startswith("/api/") or method != "GET":
                self._reject_json({"error": "비밀번호를 먼저 바꿔야 합니다", "password_change": True}, HTTPStatus.FORBIDDEN)
            else:
                self._html("", HTTPStatus.FOUND, {"Location": "/password"})
            return True
        need = self._need(method, path)
        if authmod.ROLES.get(u["role"], 0) < authmod.ROLES[need]:
            msg = f"권한이 없습니다 — {authmod.ROLE_KO[need]} 권한이 필요합니다(현재 {authmod.ROLE_KO.get(u['role'], u['role'])})"
            self.api.auth.audit(u["login"], self._ip(), "denied", f"{method} {path}", ok=False)
            # 막기만 하고 끝내지 않는다 — 무엇이 막혔는지를 담아 **승인을 요청할 길**을 함께 준다.
            # 다만 **요청으로 줄 수 없는 권한은 내밀지 않는다**(GPT 20차). 내밀어 놓고 거절하면
            # 화면과 서버가 어긋나는 것이고, 이 제품이 가장 자주 당한 결함이다.
            cap = authmod.AuthStore.REQ_MAX_ROLE
            askable = authmod.ROLES[need] <= authmod.ROLES[cap]
            if not askable:
                msg += (f" — {authmod.ROLE_KO[need]} 권한은 요청으로 드리지 않습니다."
                        " 담당 관리자에게 계정 발급을 요청하십시오")
            req = ({"kind": "role", "want": need, "action": f"{method} {path}"}
                   if self._can_request() and askable else None)
            if path.startswith("/api/") or method != "GET":
                self._reject_json({"error": msg, "request": req} if req else {"error": msg}, HTTPStatus.FORBIDDEN)
            elif askable:
                self._html(self._denied_html("접근 권한 없음", msg, "role", need, f"{method} {path}"),
                           HTTPStatus.FORBIDDEN)
            else:
                self._html(self._notice_html("접근 권한 없음", msg), HTTPStatus.FORBIDDEN)
            return True
        if not self._admin_net_ok(path):
            self.api.auth.audit(u["login"], self._ip(), "denied.adminnet", f"{method} {path}", ok=False)
            msg = "관리자 화면은 정해진 대역에서만 접속할 수 있습니다 — 사내 관리망에서 접속하십시오"
            if path.startswith("/api/") or method != "GET":
                self._reject_json({"error": msg}, HTTPStatus.FORBIDDEN)
            else:
                self._html(self._notice_html("접속 위치 제한", msg), HTTPStatus.FORBIDDEN)
            return True
        if not self._asset_ok(path):
            sname = (self.api.hub_conf or {}).get("site_name") or "이 서버"
            msg = (f"사이트 자산 현황은 해당 사이트 담당자만 볼 수 있습니다 — 관리자에게 '{sname}({self._local_site()})' 자산 조회 권한을 요청하십시오")
            self.api.auth.audit(u["login"], self._ip(), "denied.asset", f"{method} {path}", ok=False)
            site = self._local_site()
            req = {"kind": "asset", "want": site, "action": f"{method} {path}"} if self._can_request() else None
            if path.startswith("/api/") or method != "GET":
                self._reject_json({"error": msg, "request": req} if req else {"error": msg}, HTTPStatus.FORBIDDEN)
            else:
                self._html(self._denied_html("자산 조회 권한 없음", msg, "asset", site, f"{method} {path}"),
                           HTTPStatus.FORBIDDEN)
            return True
        if not self._site_ok(path):
            hc = self.api.hub_conf
            msg = f"이 서버(사이트 {hc.get('site_name')}) 에 대한 접근 권한이 없습니다 — 관리자에게 사이트 권한을 요청하십시오"
            req = {"kind": "site", "want": hc["site_id"], "action": f"{method} {path}"} if self._can_request() else None
            if method == "GET" and not path.startswith("/api/") and hc["role"] == "central":
                self._html("", HTTPStatus.FOUND, {"Location": "/hub"})
            elif path.startswith("/api/") or method != "GET":
                self._reject_json({"error": msg, "request": req} if req else {"error": msg}, HTTPStatus.FORBIDDEN)
            else:
                self._html(self._denied_html("사이트 권한 없음", msg, "site", hc["site_id"], f"{method} {path}"),
                           HTTPStatus.FORBIDDEN)
            return True
        return False

    def _audit(self, action: str, target: str = "", detail: str = "", ok: bool = True):
        u = self._u or {}
        self.api.auth.audit(u.get("login", "-"), self._ip(), action, target, detail, ok)

    def _too_many(self, login: str = "") -> bool:
        """로그인 실패 차단: 같은 IP·같은 계정 5분 10회, 같은 IP 전체 5분 60회(사내 NAT 뒤 여러 사용자를 한꺼번에 막지 않도록)."""
        now = time.time()
        ip = self._ip()
        def recent(k):
            lst = [t for t in self._fail.get(k, []) if now - t < 300]
            if lst:
                self._fail[k] = lst
            else:
                self._fail.pop(k, None)
            return len(lst)
        if len(self._fail) > 20000:
            self._fail.clear()
        return recent(ip + "|" + login.lower()[:64]) >= 10 or recent(ip) >= 60

    def _failed(self, login: str, how: str, why: str):
        now = time.time()
        for k in (self._ip() + "|" + login.lower()[:64], self._ip()):
            self._fail.setdefault(k, []).append(now)
        self.api.auth.audit(login[:64] or "-", self._ip(), "login.fail", how, why, ok=False)

    def _start_session(self, usr: dict, how: str, dest: str = "/"):
        tok = self.api.auth.new_session(usr["login"], self._ip())
        self.api.auth.audit(usr["login"], self._ip(), "login", how)
        secure = "; Secure" if self._https_ok() and not self._loopback_peer() or getattr(self.server, "tls", False) else ""
        return self._html("", HTTPStatus.FOUND, # 다른 사이트에서 넘어온 요청에는 세션을 실어 보내지 않는다(Strict).
                # 바깥 링크로 들어오면 한 번 더 눌러야 하는 불편이 있지만, 지시대로 보안을 앞세운다
                {"Location": dest, "Set-Cookie": f"lt_sid={tok}; Path=/; HttpOnly; SameSite=Strict{secure}"})

    def _form_token(self) -> str:
        """로그인한 사람이 쓰는 폼의 증표 — **세션 쿠키를 서버 열쇠로 HMAC** 한 값.

        브라우저가 붙여 주는 표시(Origin·Sec-Fetch-Site)만 보면 **둘 다 없는 요청을 통과**시킨다.
        에이전트처럼 표시를 안 붙이는 쪽을 막지 않으려던 것인데, 쿠키로 도는 쓰기 요청에는
        그 관용이 곧 구멍이다(GPT 21차). 다른 사이트는 우리 쿠키 값을 읽을 수 없으므로 이 값을
        만들 수 없고, 서버는 따로 저장할 것이 없다.
        """
        from .crypto import derive
        sid = self._cookie("lt_sid") or self._cookie("lt_session")
        if not sid:
            return ""
        return hmac.new(derive(self.api._base, "form-csrf"), sid.encode("ascii", "ignore"),
                        sha256).hexdigest()[:32]

    def _form_token_ok(self, got: str) -> bool:
        want = self._form_token()
        return bool(want) and hmac.compare_digest(str(got or ""), want)

    def _csrf_refused(self):
        return self._html(self._notice_html(
            "이 요청은 우리 화면에서 보낸 것이 아닙니다",
            "화면을 새로 고친 뒤 다시 눌러 주십시오 — 열어 둔 화면이 오래되었을 수도 있습니다."),
            HTTPStatus.FORBIDDEN)

    def _can_request(self) -> bool:
        """승인 요청을 걸 수 있는 자리인가 — **계정이 있는 로그인**일 때만."""
        c = self.api.auth_conf
        if not (c and c["mode"] in ("local", "portal")):
            return False          # 로그인 없음·단일 비밀번호에는 '내 계정' 이 없다
        u = self._u or {}
        return bool(u.get("login"))

    def _req_status(self, kind: str, want: str) -> str:
        """같은 요청이 이미 있나 — 있으면 단추 대신 상태를 보여 준다(같은 요청을 또 보내지 않게)."""
        try:
            for r in self.api.auth.my_requests((self._u or {}).get("login", "")):
                if r["kind"] == kind and r["want"] == want:
                    return r["status"]
        except Exception:
            pass
        return ""

    def _denied_html(self, title: str, msg: str, kind: str, want: str, action: str) -> str:
        """권한에 막힌 화면 — '관리자에게 문의하십시오' 로 끝내지 않고 **여기서 요청**하게 한다."""
        if not self._can_request():
            return self._notice_html(title, msg)
        st = self._req_status(kind, want)
        if st == "pending":
            box = ('<div class="hint">이미 승인을 요청했습니다 — <b>관리자 처리를 기다리고 있습니다.</b><br>'
                   '승인되면 다시 로그인한 뒤에 쓸 수 있습니다.</div>')
        else:
            was = ('<div class="hint">먼저 보낸 요청은 <b>거절</b>되었습니다 — 사유를 적어 다시 요청할 수 있습니다.</div>'
                   if st == "denied" else "")
            # 대본을 쓰지 않는다 — 평범한 폼이다(깨질 괄호가 없고, 자바스크립트가 막혀도 보낸다).
            box = (was + '<form method="post" action="/access-request">'
                   f'<input type="hidden" name="t" value="{html_escape(self._form_token())}">'
                   f'<input type="hidden" name="kind" value="{html_escape(kind)}">'
                   f'<input type="hidden" name="want" value="{html_escape(want)}">'
                   f'<input type="hidden" name="action" value="{html_escape(action[:200])}">'
                   '<label for="rq_why">왜 필요한지 적어 주십시오 — 관리자가 이 글을 봅니다</label>'
                   '<textarea id="rq_why" name="reason" rows="3" maxlength="300" style="width:100%;box-sizing:border-box;'
                   'font:inherit;padding:10px;border:1px solid #D9DEE5;border-radius:10px" '
                   'placeholder="예) 부산 IDC 장애 1차 대응을 맡아 로그 분석을 실행해야 합니다"></textarea>'
                   '<button class="btn">승인 요청 보내기</button></form>')
        body = (f'<div class="who">{_PORTAL_ICON}<b>{html_escape(title)}</b></div>'
                f'<p class="note">{html_escape(msg)}</p>' + box
                + '<div class="alt"><a href="/">처음 화면</a><a href="/logout">다른 계정으로 로그인</a></div>')
        return self._login_html("", body, title=title, sub="승인 요청")

    def _notice_html(self, title: str, msg: str) -> str:
        body = (f'<div class="who">{_PORTAL_ICON}<b>{html_escape(title)}</b></div><p class="note">{html_escape(msg)}</p>'
                '<a class="btn" href="/">처음 화면</a><div class="alt"><a href="/logout">다른 계정으로 로그인</a></div>')
        return self._login_html("", body)

    def _login_form(self, local: bool = False) -> str:
        conf = self.api.auth_conf
        if self._local_login() and not local:
            return self._email_form()
        if local and self._portal():
            return ('<div class="who">' + _PORTAL_ICON + '<span><b>비상용 관리자 로그인</b><br><small>통합 로그인 장애·초기 설정 전용 로컬 계정</small></span></div>'
                    '<form method="post" action="/login"><input type="hidden" name="local" value="1">'
                    '<label>관리자 계정</label><input name="login" autocomplete="username" required autofocus>'
                    '<label>비밀번호</label><input name="password" type="password" autocomplete="current-password" required>'
                    '<button class="btn">로그인</button></form><div class="alt"><a href="/login">통합 계정으로 로그인</a></div>')
        if self._portal():
            pc = conf["portal"]
            label = html_escape(pc.get("label") or "통합 계정")
            who = f'<div class="who">{_PORTAL_ICON}<span><b>{label}</b>으로 로그인합니다</span></div>'
            method = pc["method"]
            portal_url = pc.get("portal_url") or ""
            if method == "ldap":
                form = (who + '<form method="post" action="/login"><label>계정 ID</label><input name="login" autocomplete="username" required autofocus>'
                        '<label>비밀번호</label><input name="password" type="password" autocomplete="current-password" required>'
                        '<button class="btn">로그인</button></form>'
                        '<p class="note">비밀번호는 이 서버에 저장하지 않고 인증 서버에서 바로 확인합니다.</p>')
            elif method == "oidc":
                form = who + '<a class="btn" href="/sso/oidc/start">통합 로그인(SSO)</a><p class="note">통합 로그인 화면으로 이동했다가 돌아옵니다.</p>'
            else:
                form = (who + '<p class="note">통합 로그인(SSO)을 거쳐 <b>LogTriage</b> 메뉴로 접속하십시오.</p>'
                        + (f'<a class="btn" href="{html_escape(portal_url)}">통합 로그인 열기</a>' if re.match(r"https?://", portal_url) else ""))
            return form + '<div class="alt"><a href="/login?local=1">비상용 관리자 로그인</a></div>'
        return ('<form method="post" action="/login"><label>접속 비밀번호</label><input name="password" type="password" placeholder="접속 비밀번호" autofocus required>'
                '<button class="btn">로그인</button></form>')

    def log_message(self, fmt, *args):  # 접속 로그: stderr 한 줄
        # 22차(GPT 172): 1회용 비밀이 실린 주소는 모두 가린다 — 접속 열쇠 · 첫 관리자 설정 코드 · 에이전트 내려받기 표
        message = re.sub(r"((?:/auth/bootstrap|/setup)\?(?:[^ ]*&)?t=|[?&]ticket=)[^ &\"]+", r"\1[redacted]", fmt % args)
        sys.stderr.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {self.address_string()} {message}\n")

    # ── 서버형 전용 화면(인프라 감시·자산 관리): ui.html 과 같은 사이드바·로고를 공유 ──
    _logo_cache: str | None = None

    def _logo(self) -> str:
        if Handler._logo_cache is None:
            m = re.search(r'<img class="logomark"[^>]*>', ui_path().read_text(encoding="utf-8"))
            Handler._logo_cache = m.group(0) if m else ""
        return Handler._logo_cache

    _login_page_cache: str | None = None

    def _login_html(self, msg: str, form: str | None = None, local: bool = False, title: str = "", sub: str = "", art: str = "") -> str:
        """(주)솔리데오 브랜드 로그인 화면(gui/login.html). 파일이 없으면 예전 간이 화면으로 되돌아간다."""
        if Handler._login_page_cache is None:
            f = ui_path().parent / "login.html"
            Handler._login_page_cache = f.read_text(encoding="utf-8") if f.exists() else LOGIN_HTML
        page = Handler._login_page_cache
        logo = self._logo().replace('class="logomark"', 'style="width:42px;height:42px;border-radius:12px"')
        err = f'<div class="err">{msg}</div>' if msg and not msg.lstrip().startswith("<") else msg
        if self._plaintext_lan():   # 22차: 평문 접속이면 비밀번호를 넣기 **전에** 알린다
            err = (f'<div class="err" id="ltplain" role="alert" style="background:#FFF4E5;color:#7A4A00;border-color:#F5C26B">'
                   f'⚠ {html_escape(self.PLAINTEXT_WARN)}</div>') + (err or "")
        return (page.replace("%LOGO%", logo).replace("%FORM%", form if form is not None else self._login_form(local))
                .replace("%MSG%", err).replace("%TITLE%", html_escape(title or "LogTriage 로그인"))
                .replace("%BODY%", "key" if art == "key" else "")
                .replace("%SUB%", html_escape(sub or "회사 이메일 계정으로 로그인합니다")))

    _IC_MAIL = ('<svg viewBox="0 0 24 24" fill="none" stroke="#9AA4B2" stroke-width="1.8"><rect x="2.5" y="4.5" width="19" height="15" rx="2.5"/>'
                '<path d="m3.5 6.5 8.5 6 8.5-6"/></svg>')
    _IC_USER = ('<svg viewBox="0 0 24 24" fill="none" stroke="#9AA4B2" stroke-width="1.8"><circle cx="12" cy="8.5" r="3.6"/>'
                '<path d="M5 20c1.2-3.6 3.9-5.4 7-5.4s5.8 1.8 7 5.4"/></svg>')
    _IC_KEY = ('<svg viewBox="0 0 24 24" fill="none" stroke="#9AA4B2" stroke-width="1.8"><circle cx="8" cy="12" r="4"/>'
               '<path d="M12 12h9M17.5 12v3.5M20.5 12v2.5"/></svg>')
    _IC_LOCK = ('<svg viewBox="0 0 24 24" fill="none" stroke="#9AA4B2" stroke-width="1.8"><rect x="4" y="10.5" width="16" height="10.5" rx="2.5"/>'
                '<path d="M8 10.5V7.8a4 4 0 1 1 8 0v2.7"/><circle cx="12" cy="15.6" r="1.5" fill="#9AA4B2" stroke="none"/></svg>')

    def _email_form(self) -> str:
        d = html_escape(self._domain())
        a = self.api.accounts.conf
        return (f'<form method="post" action="/login" autocomplete="on">'
                f'<label for="lt_email">회사 이메일 (ID)</label>'
                f'<div class="field">{self._IC_MAIL}<input id="lt_email" name="email" type="email" required autocomplete="username" '
                f'spellcheck="false" maxlength="100" placeholder="hong123@{d}" title="@{d} 계정만 사용할 수 있습니다"></div>'
                f'<label for="lt_pw">비밀번호</label>'
                f'<div class="field">{self._IC_LOCK}<input id="lt_pw" name="password" type="password" required autocomplete="current-password" '
                f'maxlength="128" placeholder="비밀번호" title="{a["max_fails"]}회 틀리면 {a["lock_minutes"]}분간 잠깁니다">'
                f'<button type="button" class="eye">표시</button></div>'
                f'<div class="caps">Caps Lock 이 켜져 있습니다</div>'
                f'<button class="btn">로그인</button></form>'
                + (f'<div class="alt"><a href="/join">계정 만들기</a>'
                   f'<a href="/recover">비밀번호를 잊으셨나요?</a><a href="/login?local=1">비상용 관리자</a></div>'
                   if a["signup"] != "off" else
                   f'<div class="alt"><a href="/recover">비밀번호를 잊으셨나요?</a><a href="/login?local=1">비상용 관리자</a></div>'))

    def _join_form(self, email: str = "", name: str = "", dept: str = "") -> str:
        """계정 만들기 — 권한 칸은 **두지 않는다.**

        신청하는 사람이 자기 권한을 적어 내면 그것은 권한 체계가 아니다. 모두 조회 권한으로
        만들고, 운영·관리자 권한은 관리자가 [계정] 화면에서 올려 준다.
        """
        d = html_escape(self._domain())
        a = self.api.accounts.conf
        mode = a["signup"]
        head = ('<div class="hint">가입 신청을 접수하면 <b>관리자 승인</b> 뒤에 로그인할 수 있습니다</div>'
                if mode == "approve" else
                '<div class="hint">관리자에게 받은 <b>가입 코드</b>를 함께 적으십시오 — 승인을 따로 기다리지 않습니다</div>'
                if mode == "code" else
                '<div class="hint">계정을 만들면 <b>바로</b> 로그인할 수 있습니다</div>')
        code = ('' if mode != "code" else
                f'<label for="j_code">가입 코드</label><div class="field">{self._IC_KEY}'
                '<input id="j_code" name="code" type="text" required spellcheck="false" maxlength="20" '
                'placeholder="XXXX-XXXX-XXXX" style="letter-spacing:.12em"></div>')
        return (head
                + '<form method="post" action="/join" autocomplete="off">'
                + f'<label for="j_email">회사 이메일 (ID)</label><div class="field">{self._IC_MAIL}'
                f'<input id="j_email" name="email" type="email" required spellcheck="false" maxlength="100" '
                f'value="{html_escape(email)}" placeholder="hong123@{d}" title="@{d} 계정만 쓸 수 있습니다"></div>'
                + f'<label for="j_name">이름</label><div class="field">{self._IC_USER}'
                f'<input id="j_name" name="name" type="text" required maxlength="40" '
                f'value="{html_escape(name)}" placeholder="홍길동"></div>'
                + f'<label for="j_dept">부서(선택)</label><div class="field">{self._IC_USER}'
                f'<input id="j_dept" name="dept" type="text" maxlength="40" '
                f'value="{html_escape(dept)}" placeholder="인프라운영팀"></div>'
                + code
                + f'<label for="j_pw">비밀번호</label><div class="field">{self._IC_LOCK}'
                f'<input id="j_pw" name="password" type="password" required minlength="{a["min_length"]}" '
                'maxlength="128" autocomplete="new-password"><button type="button" class="eye">표시</button></div>'
                + f'<label for="j_pw2">비밀번호 확인</label><div class="field">{self._IC_LOCK}'
                '<input id="j_pw2" name="confirm" type="password" required maxlength="128" '
                'autocomplete="new-password"><button type="button" class="eye">표시</button></div>'
                '<div class="caps">Caps Lock 이 켜져 있습니다</div>'
                '<button class="btn">계정 만들기</button></form>'
                + f'<p class="note">ID 는 <code>@{d}</code> 계정만 쓸 수 있습니다. 비밀번호는 {a["min_length"]}자 이상, '
                f'영문 대문자·소문자·숫자·기호 중 {a["classes"]}종류 이상이며 ID·회사명·연속 문자는 쓸 수 없습니다.<br>'
                '만든 계정은 <b>조회</b> 권한입니다 — 운영·관리자 권한은 관리자가 올려 줍니다.</p>'
                '<div class="alt"><a href="/login">이미 계정이 있습니다</a>'
                '<a href="/recover">비밀번호를 잊으셨나요?</a></div>')

    def _setup_code_form(self) -> str:
        """코드가 필요한 자리(인터넷 구간)에서 막다른 화면 대신 코드를 넣을 칸을 준다(2026-09-22)."""
        hint = ('<div class="hint">아직 계정이 없는 서버입니다 — 첫 관리자 자리를 남이 먼저 차지하지 못하도록 '
                '<b>1회용 코드</b>로만 엽니다(같은 PC 에서 열어도 필요합니다)</div>')
        return (hint
                + '<form method="get" action="/setup">'
                f'<label for="t_code">초기 설정 코드</label><div class="field">{self._IC_KEY}'
                '<input id="t_code" name="t" type="text" required spellcheck="false" maxlength="64" '
                'placeholder="기동할 때 출력된 1회용 코드" style="letter-spacing:.06em"></div>'
                '<button class="btn">관리자 계정 만들기</button></form>'
                '<p class="note">코드는 서버를 기동할 때 화면·로그에 출력되고, 설치 폴더의 <code>conf/setup-code.txt</code> 에도 적힙니다'
                '(리눅스는 <code>journalctl -u logtriage</code> 또는 <code>server.log</code>).<br>'
                '계정을 하나라도 만들면 이 화면과 코드는 닫힙니다.</p>'
                '<div class="alt"><span>코드를 모르면 서버 담당자에게 요청</span><a href="/login">로그인 화면</a></div>')

    def _setup_form(self, tok: str = "") -> str:
        d = html_escape(self._domain())
        a = self.api.accounts.conf
        fa = (self.api.auth_conf or {}).get("first_admin", "")
        tok = html_escape(tok or (urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("t") or [""])[0])
        if fa:   # 설치할 때 예약해 둔 첫 관리자 — 여기서는 비밀번호만 정한다
            head = (f'<div class="hint">이 서버의 <b>첫 관리자</b>는 <b>{html_escape(fa)}</b> 로 지정되어 있습니다 — '
                    '여기서 <b>비밀번호만</b> 정하면 등록이 끝납니다</div>')
            mail = (f'<label for="s_email">회사 이메일 (ID)</label><div class="field">{self._IC_MAIL}'
                    f'<input id="s_email" type="email" value="{html_escape(fa)}" readonly tabindex="-1" '
                    'style="background:#F1F3F6;color:#5A6472"></div>')
        else:
            head = '<div class="hint">이 서버의 <b>첫 관리자 계정</b>을 만듭니다 — 만든 뒤에는 이 화면이 다시 열리지 않습니다</div>'
            mail = (f'<label for="s_email">회사 이메일 (ID)</label><div class="field">{self._IC_MAIL}'
                    f'<input id="s_email" name="email" type="email" required spellcheck="false" maxlength="100" placeholder="hong123@{d}"></div>')
        return (head
                + '<form method="post" action="/setup" autocomplete="off">'
                + f'<input type="hidden" name="t" value="{tok}">'
                + mail
                + f'<label for="s_name">이름(선택)</label><div class="field">{self._IC_USER}'
                '<input id="s_name" name="name" type="text" maxlength="40" placeholder="홍길동"></div>'
                f'<label for="s_pw">비밀번호</label><div class="field">{self._IC_LOCK}'
                f'<input id="s_pw" name="password" type="password" required minlength="{a["min_length"]}" maxlength="128"><button type="button" class="eye">표시</button></div>'
                f'<label for="s_pw2">비밀번호 확인</label><div class="field">{self._IC_LOCK}'
                '<input id="s_pw2" name="confirm" type="password" required maxlength="128"><button type="button" class="eye">표시</button></div>'
                '<div class="caps">Caps Lock 이 켜져 있습니다</div>'
                '<button class="btn">관리자 계정 만들기</button></form>'
                + f'<p class="note">{a["min_length"]}자 이상, 영문 대문자·소문자·숫자·기호 중 {a["classes"]}종류 이상.<br>'
                + ('이 계정은 <b>관리자</b> 권한과 이 서버 자산 조회 권한을 갖습니다. 다른 사람 계정은 로그인 뒤 [사용자 · 권한] 에서 발급하십시오.'
                   if not fa else
                   '이 계정은 <b>관리자</b> 권한과 이 서버 자산 조회 권한을 갖습니다. 첫 관리자를 바꾸려면 '
                   '<code>conf/auth.json</code> 의 <code>first_admin</code> 을 고치고 다시 기동하십시오.') + '</p>')

    def _recover_form(self, email: str = "", err: str = "") -> str:
        d = html_escape(self._domain())
        a = self.api.accounts.conf
        return ('<div class="hint">관리자에게 <b>비밀번호 재설정 코드</b>를 받은 뒤 입력하십시오 — 1회용이며 기본 30분간만 씁니다</div>'
                '<form method="post" action="/recover" autocomplete="off">'
                f'<label for="r_email">회사 이메일 (ID)</label><div class="field">{self._IC_MAIL}'
                f'<input id="r_email" name="email" type="email" required spellcheck="false" maxlength="100" value="{html_escape(email)}" placeholder="hong123@{d}"></div>'
                f'<label for="r_code">재설정 코드</label><div class="field">{self._IC_KEY}'
                '<input id="r_code" name="code" type="text" required spellcheck="false" maxlength="20" placeholder="XXXX-XXXX-XXXX" style="letter-spacing:.12em"></div>'
                f'<label for="r_pw">새 비밀번호</label><div class="field">{self._IC_LOCK}'
                f'<input id="r_pw" name="new" type="password" required minlength="{a["min_length"]}" maxlength="128"><button type="button" class="eye">표시</button></div>'
                f'<label for="r_pw2">새 비밀번호 확인</label><div class="field">{self._IC_LOCK}'
                '<input id="r_pw2" name="confirm" type="password" required maxlength="128"><button type="button" class="eye">표시</button></div>'
                '<div class="caps">Caps Lock 이 켜져 있습니다</div>'
                '<button class="btn">비밀번호 재설정</button></form>'
                f'<p class="note">코드는 관리자가 본인 확인 후 발급합니다(자동 메일 발송 없음). 코드를 {a["max_fails"]}회 이상 틀리면 새로 받아야 합니다.</p>'
                '<div class="alt"><span>코드가 없으면 관리자에게 요청</span><a href="/login">로그인 화면</a></div>')

    def _password_form(self, reason: str = "", err: str = "") -> str:
        a = self.api.accounts.conf
        who = html_escape((self._u or {}).get("login", ""))
        head = (f'<div class="hint">{html_escape(reason)}</div>' if reason else "")
        return (head + '<form method="post" action="/password" autocomplete="off">'
                f'<input type="hidden" name="t" value="{html_escape(self._form_token())}">'
                f'<input type="hidden" name="email" value="{who}">'
                f'<label for="p0">현재 비밀번호</label><div class="field">{self._IC_LOCK}'
                '<input id="p0" name="current" type="password" required autocomplete="current-password" maxlength="128"><button type="button" class="eye">표시</button></div>'
                f'<label for="p1">새 비밀번호</label><div class="field">{self._IC_LOCK}'
                f'<input id="p1" name="new" type="password" required autocomplete="new-password" minlength="{a["min_length"]}" maxlength="128"><button type="button" class="eye">표시</button></div>'
                f'<label for="p2">새 비밀번호 확인</label><div class="field">{self._IC_LOCK}'
                '<input id="p2" name="confirm" type="password" required autocomplete="new-password" maxlength="128"><button type="button" class="eye">표시</button></div>'
                '<div class="caps">Caps Lock 이 켜져 있습니다</div>'
                '<button class="btn">비밀번호 변경</button></form>'
                f'<p class="note">{a["min_length"]}자 이상, 영문 대문자·소문자·숫자·기호 중 {a["classes"]}종류 이상. ID·회사명·연속 문자는 쓸 수 없고 최근 {a["history"]}개는 다시 쓸 수 없습니다.</p>'
                '<div class="alt"><span>변경하면 기존 접속은 모두 끊깁니다</span><a href="/logout">로그아웃</a></div>')

    def _page(self, name: str):
        html = (ui_path().parent / name).read_text(encoding="utf-8")
        html = html.replace('<html lang="ko">', '<html lang="ko" class="lt-gnb-on">', 1)
        html = html.replace("<body>", "<body>" + GNB_HTML, 1)
        html = html.replace("</head>", DS_LINK + "</head>", 1)
        html = html.replace("</body>", "<script>" + NAV_JS + "</script></body>", 1)
        return self._html(html.replace("%LOGO%", self._logo(), 1))

    def _nms_get(self, u):
        if u.path == "/api/nms/status":
            data = self.api.nms.snapshot()
            c = self.api.collector
            data["collector"] = {"alive": c.thread.is_alive(), "heartbeat": c.heartbeat, "error": c.error,
                                 "stale": time.time() - c.heartbeat > 10}
            data["can_assets"] = authmod.asset_allowed(self._u, self._local_site())
            return self._json(self._mask_assets(data))
        if u.path == "/api/nms/history":
            tid = (urllib.parse.parse_qs(u.query).get("id") or [""])[0]
            return self._json(self._mask_assets(self.api.nms.history(tid)))
        if u.path == "/api/nms/metrics":
            q = urllib.parse.parse_qs(u.query)
            tid = (q.get("id") or [""])[0]
            try:
                secs = int((q.get("range") or ["3600"])[0])
            except ValueError:
                secs = 3600
            return self._json({"rows": self.api.nms.metrics(tid, secs), "range": secs})
        if u.path == "/api/nms/live":   # 14차 실시간 관제 — 응답 시간 표본·사용률 추이(주소·상세 글 없음)
            q = urllib.parse.parse_qs(u.query)
            try:
                secs = int((q.get("range") or ["600"])[0])
                after = int(q["after"][0]) if q.get("after") else None
                since = float(q["since"][0]) if q.get("since") else None
            except (ValueError, TypeError):
                return self._json({"error": "range·after·since 는 숫자"}, HTTPStatus.BAD_REQUEST)
            return self._json(self.api.nms.live(secs, after, since))
        if u.path == "/api/nms/settings":  # 알림 임계치(서버 공통)
            return self._json(self.api.nms.get_settings())
        if u.path == "/api/nms/procs":  # 항목의 최신 계정별 프로세스 상세
            tid = (urllib.parse.parse_qs(u.query).get("id") or [""])[0]
            d = self.api.nms.procs_detail(tid)
            if d and not authmod.asset_allowed(self._u, self._local_site()):   # 19차(GPT 119 P0-03): OS 계정 이름은 자산 권한자만
                d["users"] = [{**u, "user": f"계정 {i + 1}"} for i, u in enumerate(d.get("users") or [])]
                d["top"] = [{**t, "user": "***"} for t in d.get("top") or []]
                d["masked"] = True
            return self._json(d or {"error": "아직 수집된 프로세스 정보가 없습니다"}, HTTPStatus.OK if d else HTTPStatus.NOT_FOUND)
        if u.path == "/api/nms/agent_enroll_state":   # 19차: 간편 설치 — 코드가 쓰였는지·첫 보고가 왔는지(값은 없이)
            q = urllib.parse.parse_qs(u.query)
            try:
                return self._json(self.api.nms.enroll_state((q.get("id") or [""])[0], float((q.get("since") or ["0"])[0])))
            except ValueError:
                return self._json({"error": "since 는 숫자"}, HTTPStatus.BAD_REQUEST)
        if u.path == "/api/nms/agent_tokens":   # 발급된 대상별 토큰 목록(원문은 없음)
            return self._json({"tokens": self.api.nms.list_agent_tokens(),
                               "legacy": self.api.nms.legacy_token_state()["active"],
                               "default_days": 365, "max_days": self.api.nms.TOKEN_DAYS_MAX})
        if u.path == "/api/nms/agent":  # 에이전트 설치 안내(토큰·접속 주소)
            return self._json({"token": self.api.nms.agent_token, "url": self._agent_base() + "/api/nms/metrics",
                               "scripts": list(_AGENT_FILES), "zip": "/static/lt-agent.zip"})
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _agent_base(self) -> str:
        """에이전트가 접속할 이 서버 주소 — 브라우저가 쓴 Host 그대로(nginx 뒤면 X-Forwarded-Proto 반영)"""
        proto = (self.headers.get("X-Forwarded-Proto") or "http").split(",")[0].strip().lower()
        if proto not in ("http", "https"):
            proto = "http"
        host = self.headers.get("Host", "") or ""
        if not re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?|\[[0-9A-Fa-f:.]+\](:\d{1,5})?", host):   # agent.conf 에 그대로 들어가므로 허용 문자만
            host = f"127.0.0.1:{self.server.server_address[1]}"
        return f"{proto}://{host}"

    def _nms_post(self, u, length: int):
        if self.headers.get("X-NMS-Request") != "1" or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self._json({"error": "JSON 요청 헤더가 필요합니다"}, HTTPStatus.FORBIDDEN)
        try:
            if not 0 < length <= 16384:
                raise ValueError("요청 크기 제한: 16 KB")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("객체 형식이 필요합니다")
            if u.path == "/api/nms/save":
                return self._json(self.api.nms.save(data))
            if u.path == "/api/nms/usage":   # 14차: 사용률 수집 방식·주기만(가용성 상태는 그대로)
                r = self.api.nms.set_usage(data)
                if r["metrics"] in ("local", "snmp"):
                    self.api.collector.collect_now(r["id"])   # 바꾼 설정으로 바로 한 번
                return self._json(r)
            if u.path == "/api/nms/collect":  # 14차: [지금 갱신]
                if not isinstance(data.get("id"), str):
                    raise ValueError("감시 항목 ID 필요")
                t = next((x for x in self.api.nms.snapshot()["targets"] if x["id"] == data["id"]), None)
                if not t:
                    raise ValueError("감시 항목이 없습니다")
                if t.get("metrics") in ("local", "snmp") and t.get("enabled"):
                    self.api.collector.collect_now(t["id"])
                    return self._json({"ok": True, "note": "지금 수집합니다 — 1~2초 뒤 화면에 반영됩니다"})
                if t.get("metrics") == "agent":
                    return self._json({"ok": True, "note": "에이전트는 원격 서버가 보내는 값이라 당길 수 없습니다 — 다음 보고(최대 "
                                       f"{self.api.nms.usage_interval(t['id'])}초) 때 반영됩니다"})
                return self._json({"ok": False, "note": "이 항목은 사용률을 수집하지 않습니다(사용 안 함이거나 수집 방식 '안 함')"})
            if u.path == "/api/nms/delete":
                if not isinstance(data.get("id"), str):
                    raise ValueError("감시 항목 ID 필요")
                self.api.nms.delete(data["id"])
                return self._json({"ok": True})
            if u.path == "/api/nms/ack":
                if type(data.get("id")) is not int:
                    raise ValueError("장애 ID 필요")
                self.api.nms.ack(data["id"])
                return self._json({"ok": True})
            if u.path == "/api/nms/agent_enroll":      # 19차 간편 설치 명령 — 1회용 등록 코드(30분)와 설치 스크립트 지문
                r = self.api.nms.issue_enroll(str(data.get("id", "")), (self._u or {}).get("login", ""))
                self._audit("nms.enroll.issue", r["name"])
                return self._json({**r, "base": self._agent_base(), "setup_sha": hashlib.sha256(agent_setup_script()).hexdigest()})
            if u.path == "/api/nms/agent_token":       # 대상별 토큰 발급 — 원문은 이 응답에서 한 번만
                r = self.api.nms.issue_agent_token(data.get("target_id", ""), data.get("label", ""),
                                                   data.get("days", 365), (self._u or {}).get("login", ""))
                self._audit("nms.token.issue", r.get("target_id") or "(공용)",
                            f"유효기간 {'무기한' if not r['days'] else str(r['days']) + '일'}")
                out = dict(r)
                out["ticket"] = self._dl_ticket_new(r["token"])   # 이 표로 5분 안에 한 번만 내려받는다
                out["ticket_ttl"] = self.DL_TICKET_TTL
                return self._json(out)
            if u.path == "/api/nms/agent_token_revoke":
                r = self.api.nms.revoke_agent_token(data.get("id", ""))
                self._audit("nms.token.revoke", str(data.get("id", ""))[:16])
                return self._json(r)
            if u.path == "/api/nms/agent_token_legacy_off":   # 예전 공용 토큰 폐기
                r = self.api.nms.disable_legacy_token()
                self._audit("nms.token.legacy_off", "(공용)", "공용 토큰 폐기")
                return self._json(r)
            if u.path == "/api/nms/settings":
                return self._json(self.api.nms.set_settings(data))
            if u.path in ("/api/nms/snmp_test", "/api/nms/snmp_walk"):  # 장비 SNMP 연결 확인·OID 탐색(등록 전 화면에서 사용)
                from . import snmp as _snmp
                import ipaddress as _ip
                try:
                    host = str(_ip.ip_address(data.get("address", "")))
                except ValueError:
                    raise ValueError("IP 주소가 필요합니다") from None
                comm = data.get("community")
                if not comm and isinstance(data.get("id"), str):   # 편집 중이면 저장된 community 사용
                    with self.api.nms.db() as db:
                        r = db.execute("SELECT snmp_community FROM targets WHERE id=?", (data["id"],)).fetchone()
                        comm = self.api.nms._sc_dec(r[0], data["id"]) if r else ""   # 저장은 암호문
                if not isinstance(comm, str) or not comm or len(comm) > 64:
                    raise ValueError("community 가 필요합니다")
                port = data.get("port", 161)
                if type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError("port: 1~65535")
                if not self._snmp_slot.acquire(blocking=False):
                    return self._json({"error": "다른 SNMP 조회가 진행 중입니다 — 잠시 후 다시"}, HTTPStatus.TOO_MANY_REQUESTS)
                try:
                    if u.path == "/api/nms/snmp_test":
                        oids = [o for o in (data.get("oids") or []) if isinstance(o, str) and o.strip()][:10]
                        for o in oids:
                            if not OID_RE.fullmatch(o.strip()):
                                raise ValueError(f"OID 형식 오류: {o}")
                        want = [_snmp.SYS_DESCR, _snmp.SYS_NAME, _snmp.SYS_UPTIME] + oids
                        vals = _snmp.get(host, want, comm, port, timeout=2.0, retries=1)
                        return self._json({"ok": True, "values": [{"oid": o, "value": vals.get(o.strip().strip('.'))} for o in want]})
                    base = str(data.get("base") or "1.3.6.1.2.1.1").strip()
                    if not OID_RE.fullmatch(base):
                        raise ValueError("기준 OID 형식 오류")
                    rows = _snmp.walk(host, base, comm, port, timeout=2.0, max_entries=_snmp.WALK_MAX, budget=20.0)
                    return self._json({"ok": True, "base": base, "rows": [{"oid": o, "value": v} for o, v in rows], "truncated": len(rows) >= _snmp.WALK_MAX})
                except _snmp.SnmpError as e:
                    return self._json({"error": f"SNMP: {e}"}, HTTPStatus.BAD_GATEWAY)
                finally:
                    self._snmp_slot.release()
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, TypeError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        except Exception as e:
            sys.stderr.write(f"[NMS] {type(e).__name__}: {e}\n")
            return self._json({"error": "NMS 저장소 오류: 서버 로그 확인"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    # 내려받기 표(1회용): 발급은 POST 에서만 하고, GET 은 이미 발급된 토큰을 파일에 넣기만 한다.
    #   조회(GET)가 상태를 바꾸면 중복 클릭·미리 가져오기만으로 쓰지 않는 토큰이 쌓인다.
    _dl_tickets: dict = {}          # 표 → (토큰, 만든 시각). 한 번 쓰면 사라지고 5분이면 만료
    _dl_lock = threading.Lock()
    DL_TICKET_TTL = 300

    @classmethod
    def _dl_ticket_new(cls, token: str) -> str:
        t = secrets.token_urlsafe(18)
        now = time.time()
        with cls._dl_lock:
            for k, (_, at) in list(cls._dl_tickets.items()):
                if now - at > cls.DL_TICKET_TTL:
                    cls._dl_tickets.pop(k, None)
            if len(cls._dl_tickets) > 200:
                cls._dl_tickets.clear()
            cls._dl_tickets[t] = (token, now)
        return t

    @classmethod
    def _dl_ticket_use(cls, t: str) -> str:
        with cls._dl_lock:
            got = cls._dl_tickets.pop(t, None)
        if not got or time.time() - got[1] > cls.DL_TICKET_TTL:
            return ""
        return got[0]

    def _agent_token_for(self, u) -> str:
        """내려받기 파일에 넣을 토큰. ?ticket=… 이면 방금 발급한 그 토큰, 없으면 공용 토큰(살아 있을 때만).

        GET 은 더 이상 토큰을 만들지 않는다 — 발급은 [모니터링] 화면이 POST 로 한 번만 한다."""
        q = urllib.parse.parse_qs(u.query)
        tk = (q.get("ticket") or [""])[0].strip()
        if tk:
            tok = self._dl_ticket_use(tk)
            if tok:
                return tok
            self._audit("nms.token.ticket_miss", "", "만료되었거나 이미 쓴 내려받기 표", ok=False)
        return self.api.nms.agent_token

    def _agent_enroll(self, length: int):
        """설치 스크립트가 등록 코드와 호스트명을 내면 그 대상 전용 토큰을 준다. 보낸 곳 IP 는 소켓 피어(우리 nginx 뒤면 그 nginx 가 적어 준 값)."""
        addr = self._ip()
        if not enroll_allow(addr):
            self._audit("nms.enroll", addr, "시도 제한", ok=False)
            return self._json({"error": "등록 시도가 너무 많습니다 — 10분 뒤 다시 하십시오"}, HTTPStatus.TOO_MANY_REQUESTS)
        try:
            if not 0 < length <= 1024:
                raise ValueError("요청 크기 오류")
            v = json.loads(self.rfile.read(length))
            if not isinstance(v, dict):
                raise ValueError("JSON 객체 필요")
            r = self.api.nms.redeem_enroll(str(v.get("code", "")), addr, str(v.get("hostname", ""))[:120])
        except PermissionError as e:
            self._audit("nms.enroll", addr, str(e)[:120], ok=False)
            return self._json({"error": str(e)}, HTTPStatus.FORBIDDEN)
        except (ValueError, TypeError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        self._audit("nms.enroll", f"{r['name']} ← {addr}", "간편 설치 토큰 발급")
        return self._json({"ok": True, **r})

    def _agent_push(self, length: int):
        from .nms import validate_metrics
        tok = self.headers.get("X-Agent-Token", "")
        who = self.api.nms.check_agent_token(tok)
        # 출발지 주소: 소켓 peer IP. 우리 nginx(같은 호스트 · 비밀 머리글)를 거쳤을 때만 그 nginx 가 적어 준 X-Real-IP. 본문 address 는 신뢰하지 않음
        addr = self._ip()
        if who is None:
            self.api.nms.note_reject(addr, "", "에이전트 토큰이 맞지 않습니다(출처 확인 안 됨) — [편집]에서 이 대상 토큰을 다시 발급해 에이전트에 넣으십시오", authed=False)
            return self._json({"error": "에이전트 토큰이 맞지 않습니다"}, HTTPStatus.UNAUTHORIZED)
        if who.get("error"):        # 기한 만료·폐기 — 왜 막혔는지 알려 준다
            self.api.nms.note_reject(addr, "", who["error"], authed=False)
            return self._json({"error": who["error"]}, HTTPStatus.UNAUTHORIZED)
        try:
            if not 0 < length <= 65536:
                raise ValueError("요청 크기 제한: 64 KB")
            data = json.loads(self.rfile.read(length))
            m = validate_metrics(data)
            host = str(data.get("hostname") or "")[:64]
            hits = self.api.nms.agent_targets(address=addr, hostname=data.get("hostname"))
            if who.get("target_id"):
                # 대상별 토큰: 그 대상의 수치만 받는다. 주소·호스트명이 그 대상과 맞아야 한다(토큰만으로는 부족)
                hits = [h for h in hits if h["id"] == who["target_id"]]
                if not hits:
                    self.api.nms.note_reject(addr, host, f"이 대상 전용 토큰인데 보낸 주소({addr})·호스트명({host or '없음'})이 그 감시 항목과 맞지 않습니다 — "
                                             f"항목의 IP 를 {addr} 로 고치거나 항목 이름을 호스트명 {host or '(에이전트 서버의 hostname)'} 으로 바꾸십시오",
                                             who["target_id"])
                    return self._json({"error": f"이 토큰은 다른 감시 대상의 것입니다 — 보낸 주소({addr})·호스트명이 발급 대상과 맞지 않습니다"},
                                      HTTPStatus.FORBIDDEN)
            if not hits:
                self.api.nms.note_reject(addr, host, f"주소 {addr}·호스트명 {host or '(없음)'} 과 맞는 '에이전트' 수집 항목이 없습니다 — "
                                         f"감시 항목의 IP 를 {addr} 로 하거나 이름을 {host or '호스트명'} 으로 하고 수집 방식을 '원격 서버 — 에이전트'로 두십시오")
                return self._json({"error": f"이 주소({addr})/호스트명으로 등록된 '에이전트' 수집 항목이 없습니다 — [모니터링]에서 자원 사용률 수집을 '에이전트'로 등록하십시오"}, HTTPStatus.NOT_FOUND)
            self.api.nms.clear_reject(addr, host)
            self.api.nms.clear_reject(addr, "")
            try:
                for h in hits:
                    self.api.nms.record_metrics(h["id"], m, min_interval=5)
            except ValueError as e:
                return self._json({"error": str(e)}, HTTPStatus.TOO_MANY_REQUESTS)
            # 14차: 화면에서 정한 수집 주기를 에이전트에 알려 준다(새 에이전트는 다음 전송부터 따른다 · 옛 에이전트는 무시)
            return self._json({"ok": True, "targets": [h["name"] for h in hits],
                               "interval": min(self.api.nms.usage_interval(h["id"]) for h in hits)})
        except (ValueError, TypeError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        except Exception as e:
            sys.stderr.write(f"[NMS agent] {type(e).__name__}: {e}\n")
            return self._json({"error": "저장 오류: 서버 로그 확인"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    _import_slot = threading.BoundedSemaphore(1)  # 자원 업로드는 한 번에 1건
    _snmp_slot = threading.BoundedSemaphore(1)  # SNMP 연결 테스트·OID 찾기 전용(업로드 슬롯과 분리)

    def _send_file(self, name: str, data: bytes, ctype: str):
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(name))
        self.send_header("X-Content-Type-Options", "nosniff")
        # 내려주는 것은 분석 결과·보고서·대장이다 — 고객 로그에서 뽑은 내용이 들어 있다.
        # 공용 PC 의 브라우저 캐시나 사내 프록시에 남겨 둘 것이 아니다(2026-10-02).
        self.send_header("Cache-Control", "no-store, private, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        return self.wfile.write(data)

    def _inventory_get(self, u):
        q = urllib.parse.parse_qs(u.query)
        if u.path in ("/api/inventory/doc", "/api/inventory/doc/original", "/api/inventory/doc/export", "/api/inventory/list"):
            self._audit("asset.view", u.path + ("?" + u.query if u.query else ""))
        XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        try:
            if u.path == "/api/inventory/docs":
                docs = self.api.docs.list()
                for d in docs:  # 시트 이름 요약
                    try:
                        d["sheet_names"] = self.api.docs.sheet_names(d["id"])
                    except Exception:
                        d["sheet_names"] = []
                return self._json({"docs": docs})
            if u.path == "/api/inventory/doc":
                return self._json(self.api.docs.get(int((q.get("id") or ["0"])[0])))
            if u.path == "/api/inventory/doc/original":
                name, data = self.api.docs.original(int((q.get("id") or ["0"])[0]))
                return self._send_file(name, data, XLSX)
            if u.path == "/api/inventory/doc/edits":  # 변경 이력
                return self._json({"edits": self.api.docs.edits(int((q.get("id") or ["0"])[0]))})
            if u.path == "/api/inventory/doc/export":
                name, data = self.api.docs.export_xlsx(int((q.get("id") or ["0"])[0]), (q.get("sheet") or [""])[0], (q.get("q") or [""])[0],
                                                       (q.get("hidden") or ["0"])[0] == "1")
                return self._send_file(name, data, XLSX)
        except ValueError as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        if u.path == "/api/inventory/list":
            q = urllib.parse.parse_qs(u.query)
            try:
                return self._json(self.api.inventory.list((q.get("sheet") or ["서버"])[0], (q.get("q") or [""])[0], (q.get("page") or ["1"])[0]))
            except ValueError as e:
                return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        if u.path == "/api/inventory/template":
            raw = (Path(__file__).with_name("resource-template.xlsx")).read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote("자원정보.xlsx"))
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            return self.wfile.write(raw)
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    _INV_JSON = ("/api/inventory/doc/delete", "/api/inventory/doc/header", "/api/inventory/doc/edit", "/api/inventory/doc/undo")

    def _inventory_post(self, u, length: int):
        if self.headers.get("X-NMS-Request") != "1":
            return self._json({"error": "요청 헤더가 필요합니다"}, HTTPStatus.FORBIDDEN)
        if u.path in self._INV_JSON:  # 작은 JSON 요청(편집·삭제·제목 행)은 업로드 슬롯과 무관 — DB 트랜잭션(BEGIN IMMEDIATE)이 직렬화
            try:
                if not 0 < length <= 2 * 1024 * 1024:
                    raise ValueError("요청 크기 제한: 2 MB")
                d = json.loads(self.rfile.read(length))
                if u.path == "/api/inventory/doc/delete":
                    return self._json(self.api.docs.delete(int(d.get("id"))))
                if u.path == "/api/inventory/doc/header":
                    return self._json(self.api.docs.set_header(int(d.get("id")), str(d.get("sheet", "")), int(d.get("header_rows", 1))))
                actor = self._ip()   # 우리 nginx 뒤에서만 그 nginx 가 적어 준 주소(X-Forwarded-For 첫 값은 위조 가능)
                if u.path == "/api/inventory/doc/edit":
                    return self._json(self.api.docs.edit(int(d.get("id")), str(d.get("sheet", "")), d.get("rev"), d.get("ops"), actor=actor))
                return self._json(self.api.docs.undo(int(d.get("id")), d.get("rev"), str(d.get("sheet") or ""), actor=actor))
            except EditConflict as e:
                return self._json({"error": str(e), "conflict": True}, HTTPStatus.CONFLICT)
            except sqlite3.OperationalError as e:   # database is locked/busy — 다른 편집이 잠금 보유
                sys.stderr.write(f"[inventory] sqlite {e}\n")
                return self._json({"error": "다른 편집이 처리 중입니다 — 잠시 후 다시 시도하십시오"}, HTTPStatus.SERVICE_UNAVAILABLE)
            except (ValueError, TypeError, AttributeError) as e:
                return self._json({"error": str(e) if isinstance(e, ValueError) else "요청 형식 오류"}, HTTPStatus.BAD_REQUEST)
            except Exception as e:
                sys.stderr.write(f"[inventory] {type(e).__name__}: {e}\n")
                return self._json({"error": "자원 처리 오류: 서버 로그 확인"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        if not self._import_slot.acquire(blocking=False):
            return self._json({"error": "다른 자원 업로드가 처리 중입니다"}, HTTPStatus.TOO_MANY_REQUESTS)
        try:
            if not 0 < length <= 10 * 1024 * 1024:
                raise ValueError("파일/요청 크기 제한: 10 MB")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("업로드가 중단되었습니다")
            if u.path == "/api/inventory/inspect":
                return self._json(inspect_workbook(raw))
            if u.path == "/api/inventory/docs":  # 문서 업로드(원본 그대로)
                name = (urllib.parse.parse_qs(u.query).get("name") or ["workbook.xlsx"])[0]
                result = self.api.docs.add(raw, name)
                try:
                    self.api.automation.wake_assets(result['name'])
                except Exception:
                    __import__('logging').exception('Uploaded asset document; immediate sync scheduling failed')
                    result['automation_warning'] = '즉시 동기화 예약 실패; 다음 정기 실행에서 처리합니다'
                return self._json(result)
            if u.path == "/api/inventory/import/preview":
                # 남이 준 아무 표나 받아 우리 기준 항목으로 읽어 본다(저장은 하지 않는다).
                # 저장은 안 해도 서버에서 XML·ZIP·CSV 파서를 돌리는 '능동' 작업이다 —
                # 보기 권한만으로는 부족하고 운영 권한부터 허용한다(GPT 교차 검토).
                if authmod.ROLES.get(self._u.get("role"), 0) < 2:
                    return self._json({"error": "파일을 읽어 보는 것은 운영 권한부터 할 수 있습니다"},
                                      HTTPStatus.FORBIDDEN)
                q = urllib.parse.parse_qs(u.query)
                name = (q.get("name") or ["asset.xlsx"])[0]
                kind = (q.get("type") or [""])[0]
                try:
                    from . import asset_import
                    # 현장이 더한 항목까지 채운다 — 조정은 서버 금고에서만 읽는다
                    extra, levels = self.api._asset_overlay(kind)
                    # 고객 자산명이 들어 있지만 _json() 이 이미 Cache-Control: no-store 를 붙인다
                    return self._json(asset_import.preview(raw, name, kind,
                                                           extra=extra, levels=levels))
                except ValueError as e:
                    return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
            if u.path == "/api/inventory/apply":
                name = (urllib.parse.parse_qs(u.query).get("name") or ["resources.xlsx"])[0]
                return self._json(self.api.inventory.apply(raw, name))
            if u.path == "/api/inventory/save":
                return self._json(self.api.inventory.save_resource(json.loads(raw)))
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, TypeError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        except Exception as e:
            sys.stderr.write(f"[inventory] {type(e).__name__}: {e}\n")
            return self._json({"error": "자원 처리 오류: 서버 로그 확인"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        finally:
            self._import_slot.release()

    # ── GET ──
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if not self._begin():
            return None
        if u.path == "/setup":
            if not self._local_login():
                return self._json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
            if not self._needs_setup():
                return self._html("", HTTPStatus.FOUND, {"Location": "/login"})
            if not self._setup_ok():
                if (urllib.parse.parse_qs(u.query).get("t") or [""])[0]:
                    self._failed("(setup)", "setup", "초기 설정 코드 불일치")   # 틀린 코드를 들고 왔다
                return self._html(self._login_html("", self._setup_code_form(), title="초기 설정 코드",
                                                   sub="인터넷 구간에서 첫 계정을 만들 때만 필요합니다", art="key"),
                                  HTTPStatus.FORBIDDEN)
            return self._html(self._login_html("", self._setup_form(), title="관리자 계정 만들기",
                                               sub="처음 기동 — 이 서버를 쓸 첫 계정을 등록합니다", art="key"))
        if u.path == "/recover":
            if not self._local_login():
                return self._json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
            return self._html(self._login_html("", self._recover_form(), title="비밀번호 재설정",
                                               sub="관리자가 발급한 재설정 코드로 새 비밀번호를 정합니다", art="key"))
        if u.path == "/join":
            if not self._local_login():
                return self._json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
            if self._needs_setup():   # 계정이 하나도 없는 서버에서는 **첫 관리자**부터 만든다
                return self._html("", HTTPStatus.FOUND, {"Location": "/setup"})
            if self.api.accounts.conf["signup"] == "off":
                return self._html(self._login_html(
                    "이 서버는 직접 가입을 받지 않습니다 — 관리자에게 계정 발급을 요청하십시오",
                    self._login_form(), title="LogTriage 로그인", sub="직접 가입 받지 않음"), HTTPStatus.FORBIDDEN)
            return self._html(self._login_html("", self._join_form(), title="계정 만들기",
                                               sub="회사 이메일로 본인 계정을 만듭니다", art="key"))
        if u.path == "/login":
            q = urllib.parse.parse_qs(u.query)
            if self._needs_setup():
                return self._html("", HTTPStatus.FOUND, {"Location": "/setup"})
            if self._portal() and self.api.auth_conf["portal"]["method"] == "header" and "local" not in q and self._user():
                return self._html("", HTTPStatus.FOUND, {"Location": "/"})
            msg = html_escape(self._auth_msg)
            if (q.get("kicked") or [""])[0] == "1" and not msg:
                msg = ('<div class="err">다른 곳에서 같은 계정으로 로그인하여 이 접속은 종료되었습니다 — '
                       '본인이 한 로그인이 아니라면 비밀번호를 바꾸고 관리자에게 알리십시오</div>')
            return self._html(self._login_html(msg, local=(q.get("local") or [""])[0] == "1"))
        if u.path == "/logout":
            self._user()
            if self._u:
                self._audit("logout")
            self.api.auth.drop_session(self._cookie("lt_sid"))
            m = re.search(r"lt_session=([0-9a-f]{32})", self.headers.get("Cookie", ""))
            if m and not self.desktop:
                self._sessions.discard(m.group(1))
            dest = "/login"
            if self._portal() and self.api.auth_conf["portal"].get("logout_url", "").startswith(("http://", "https://")):
                dest = self.api.auth_conf["portal"]["logout_url"]
            return self._html("", HTTPStatus.FOUND, {"Location": dest, "Set-Cookie": "lt_sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
        if u.path == "/password":
            if not self._local_login():
                return self._json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
            if self._user() is None:
                return self._html("", HTTPStatus.FOUND, {"Location": "/login"})
            acc = self.api.accounts.list_one(self._u["login"]) or {}
            reason = ("처음 로그인입니다 — 임시 비밀번호를 본인만 아는 비밀번호로 바꿔 주십시오" if acc.get("must_change")
                      else ("비밀번호 사용 기간이 지났습니다 — 새 비밀번호로 바꿔 주십시오" if self._must_change() else ""))
            return self._html(self._login_html("", self._password_form(reason), title="비밀번호 변경",
                                               sub=html_escape(self._u["login"])))
        if u.path == "/agent/setup.sh" or u.path.startswith("/agent/files/"):   # 19차 간편 설치 — 비밀 없음, 정해진 파일만
            try:
                body = agent_setup_script() if u.path == "/agent/setup.sh" else agent_plain(u.path.rsplit("/", 1)[-1])
            except (OSError, ValueError):
                body = None
            if body is None:
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        if u.path.startswith("/sso/"):
            return self._sso(u)
        if u.path == "/auth/bootstrap" and self.desktop:
            return self._bootstrap(u)
        if u.path == "/healthz":
            try:
                db = {"kind": self.api.store.kind, "incidents": self.api.store.count()}
            except Exception as e:
                return self._json({"ok": False, "app": "LogTriage", "version": __version__,
                                   "build": BUILD, "build_id": buildid.current(),
                                   "db_error": str(e)}, HTTPStatus.SERVICE_UNAVAILABLE)
            from .crypto import backend as _cbk
            # 이 응답은 로그인 없이도 열린다(에이전트 설치 확인용) — 구현 이름까지 알려 주지 않는다
            # build 는 사람이 보는 제품 판(1.0.0), build_id 는 **코드가 실제로 바뀌었는지** 가리는
            # 값이다. 제품 판을 고정했으므로 "패치했는데 화면이 그대로" 는 build_id 로만 가려낼 수
            # 있다. **디스크를 다시 읽지 않는다** — 기동할 때 담아 둔 값이다(GPT 8차).
            # build_id 는 **배포물 지문**(엔진 + 기동 스크립트)이고, code_id 는 돌고 있는
            # 코드에서 계산한 값이다. 둘을 같이 싣는 까닭: 앞의 것은 '패치가 먹었는가',
            # 뒤의 것은 '설치 뒤에 누가 손댔는가' 를 가린다.
            out = {"ok": True, "app": "LogTriage", "version": __version__, "build": BUILD,
                   "build_id": buildid.current(), "code_id": buildid.code(),
                   "crypto_ok": _cbk() == "cryptography", "db": db}
            if buildid.modified():
                out["code_modified"] = True
            return self._json(out)
        if self._guard("GET", u.path):
            return None
        if u.path == "/api/me":
            return self._json(self._me())
        if u.path == "/api/access/mine":
            return self._json({"requests": self.api.auth.my_requests((self._u or {}).get("login", "")),
                               "kinds": authmod.AuthStore.REQ_KO})
        if u.path in ("/hub", "/admin"):
            return self._page("hub.html" if u.path == "/hub" else "admin.html")
        if u.path == "/board":
            return self._page("board.html")
        if u.path.startswith("/api/board/"):
            return self._board_get(u)
        if u.path.startswith("/api/hub/"):
            return self._hub_get(u)
        if u.path.startswith("/api/admin/"):
            return self._admin_get(u)
        if u.path == "/automation":
            return self._page("automation.html")
        if u.path == "/api/automation/status":
            st = self.api.automation.status()
            st["can_admin"] = authmod.ROLES.get(self._u.get("role"), 0) >= 3
            st["can_operate"] = authmod.ROLES.get(self._u.get("role"), 0) >= 2
            st["can_admin"] = authmod.ROLES.get(self._u.get("role"), 0) >= 3   # 16차: 업로드 원본 정리 단추(서버 관문도 관리자)
            return self._json(st)
        if u.path == "/api/automation/notices":    # 상단 알림 종 — 가볍게(안 읽은 수 + 최근 몇 건)
            q = urllib.parse.parse_qs(u.query)
            try:
                lim = int((q.get("limit") or ["20"])[0])
            except ValueError:
                lim = 20
            return self._json(self.api.automation.notices(lim))
        if u.path == "/api/automation/download":   # 산출물·백업 바로 내려받기(운영 권한, 백업은 관리자)
            q = urllib.parse.parse_qs(u.query)
            area, name = (q.get("area") or [""])[0], (q.get("name") or [""])[0]
            if area == "backups" and authmod.ROLES.get(self._u.get("role"), 0) < 3:
                return self._json({"error": "백업 파일은 관리자만 내려받을 수 있습니다(비밀번호·토큰 포함 가능)"}, HTTPStatus.FORBIDDEN)
            f = self.api.automation.file_path(area, name)
            if not f:
                return self._json({"error": "파일이 없습니다"}, HTTPStatus.NOT_FOUND)
            self._audit("download", f"{area}/{f.name}")
            ctype = {".pdf": "application/pdf", ".html": "text/html; charset=utf-8", ".json": "application/json"}.get(f.suffix.lower(), "application/octet-stream")
            if (q.get("inline") or [""])[0] == "1" and f.suffix.lower() in (".pdf", ".html"):
                data = f.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Disposition", "inline; filename*=UTF-8''" + urllib.parse.quote(f.name))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
                self.send_header("Cache-Control", "no-store, private, max-age=0")  # 분석 결과를 캐시에 남기지 않는다
                self.send_header("Pragma", "no-cache")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            return self._send_file(f.name, f.read_bytes(), ctype)
        if u.path.startswith("/static/"):  # 서버형 화면 공용 자원(gui/ 의 허용 파일만)
            name = Path(u.path).name
            f = ui_path().parent / name
            ctype = "text/css; charset=utf-8"
            if name == "lt-agent.zip":  # 설치형 에이전트(압축 해제 후 실행, root 불필요) — agent.conf 에 이 서버 주소·토큰을 채워 준다
                body = agent_zip(self._agent_base(), self._agent_token_for(u))
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", "attachment; filename=lt-agent.zip")
                self.send_header("Cache-Control", "no-store, private, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if name in _AGENT_FILES:  # 자원 사용률 에이전트 스크립트(개별) — 주소·토큰을 채워 준다
                f = agent_dir() / name
                ctype = "text/plain; charset=utf-8"
            if name not in ("_srv_common.css", "_ds.css") + _AGENT_FILES or not f.exists():
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            body = f.read_bytes()
            secret = name in _AGENT_FILL
            if secret:
                body = agent_fill(name, body, self._agent_base(), self._agent_token_for(u))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", ctype)
            if ctype.startswith("text/plain"):
                self.send_header("Content-Disposition", f"attachment; filename={name}")
            self.send_header("Content-Length", str(len(body)))
            # 토큰이 든 파일은 캐시에 남기지 않는다. 토큰이 없는 공용 스타일도 마찬가지로
            # 두는데, 까닭이 다르다 — **새 화면에 옛 스타일**이 붙는 짝 어긋남을 막기
            # 위해서다. 8KB 라 다시 받는 값이 싸다.
            self.send_header("Cache-Control", "no-store, private, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(body)
        if u.path == "/nms":
            return self._page("nms.html")
        if u.path == "/nms/live":   # 14차 실시간 관제 — 사이드바 없는 전체 화면(관제실 모니터용), 권한은 /nms 와 같다
            # 공통 디자인(_ds.css)은 밝은 화면용이라 넣지 않는다 — 이 화면은 자체 어두운 테마만(제목 글자가 공통 색으로 덮였다)
            return self._html((ui_path().parent / "nms_live.html").read_text(encoding="utf-8"))
        if u.path == "/resources":
            return self._page("inventory.html")
        if u.path == "/resources/view":
            return self._page("inventory_view.html")
        if u.path.startswith("/api/nms/"):
            return self._nms_get(u)
        if u.path.startswith("/api/inventory/"):
            return self._inventory_get(u)
        if u.path in ("/", "/index.html"):
            html = ui_path().read_text(encoding="utf-8")
            native = getattr(self, "native", self.desktop)   # 동반 실행기(브라우저)는 desktop 인증이지만 네이티브 대화상자는 없다(r2)
            shim = SHIM.replace("%NAMES%", json.dumps(list(API_NAMES))).replace("%NATIVE%", "true" if native else "false").replace("%NAV%", NAV_JS)
            html = html.replace("<head>", "<head>" + shim, 1) if "<head>" in html else shim + html
            html = html.replace("</head>", DS_LINK + "</head>", 1)
            return self._html(html)
        if u.path.startswith("/reports/"):
            name = urllib.parse.unquote(u.path[len("/reports/"):])
            dirs = self.api.report_dirs() if hasattr(self.api, "report_dirs") else [self.api._base / "reports"]
            rep = dirs[0]
            if not name:
                files = sorted((q for d in dirs if d.is_dir() for q in d.glob("*") if q.is_file()),
                               key=lambda p: p.stat().st_mtime, reverse=True)
                files = [p for p in files if self._report_file_ok(p.name)]
                items = "".join(f'<li><a href="/reports/{urllib.parse.quote(p.name)}">{p.name}</a> '
                                f'<small>{p.stat().st_size // 1024} KB</small></li>' for p in files[:200])
                return self._html(f"<!doctype html><meta charset=utf-8><title>보고서</title><body style='font-family:system-ui'>"
                                  f"<h3>생성된 보고서</h3><ul>{items or '<li>없음</li>'}</ul></body>")
            safe = Path(name).name
            p = next((d / safe for d in dirs if (d / safe).is_file()), None)
            if p is None:
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            if not self._report_file_ok(p.name):
                self._audit("download.denied", "reports/" + p.name, "다른 부서 계정이 등록한 분석", ok=False)
                return self._json({"error": "다른 부서 계정이 등록한 분석의 보고서입니다 — 등록한 담당자와 같은 부서만 받습니다(장비 정보 보호)"},
                                  HTTPStatus.FORBIDDEN)
            self._audit("download", "reports/" + p.name)
            data = p.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urllib.parse.quote(p.name)}")
            self.send_header("Cache-Control", "no-store, private, max-age=0")  # 보고서 — 캐시에 남기지 않는다
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    # ── POST / PUT ──
    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        if not self._begin():
            return None
        length = int(self.headers.get("Content-Length") or 0)
        if not self._same_origin():
            return self._reject_json({"error": "다른 출처(Origin)의 요청은 허용하지 않습니다"}, HTTPStatus.FORBIDDEN)
        if u.path == "/login":
            if not 0 < length <= 4096:
                return self._reject_json({"error": "요청 크기 오류"}, HTTPStatus.BAD_REQUEST)
            body = urllib.parse.parse_qs(self._body(length).decode("utf-8", "replace"))
            g = lambda k: (body.get(k) or [""])[0]
            local = g("local") == "1"
            # 23차: 이메일 로그인은 실패를 '주소|이메일' 로 적는데(_failed) 막을 때는 '(공용)' 으로 세어, 계정마다 5분 10회가 아니라
            # 주소마다 60회에야 막혔다(RHEL 검증 매뉴얼 V55 를 쓰다 발견) — 적는 열쇠와 세는 열쇠를 같게
            who = (g("email").strip() if (self._local_login() and not local)
                   else g("login").strip() if (self._portal() or local) else "(공용)")
            if self._too_many(who):
                return self._html(self._login_html("로그인 실패가 많아 5분 동안 로그인을 막았습니다 — 잠시 후 다시 시도하십시오", local=local), HTTPStatus.TOO_MANY_REQUESTS)
            if self._local_login() and not local:
                email = g("email").strip()
                try:
                    usr = self.api.accounts.verify(email, g("password"), self._ip())
                except authmod.AuthError as e:
                    self._failed(email[:64], "email", str(e))
                    return self._html(self._login_html(html_escape(str(e))), HTTPStatus.UNAUTHORIZED)
                dest = "/password" if usr.get("must_change") else "/"
                return self._start_session(usr, "email", dest)
            if self._portal():
                login = g("login").strip()
                if local:
                    usr = self.api.auth.verify_local(login, g("password"))
                    if usr:
                        return self._start_session(usr, "local")
                    self._failed(login, "local", "계정 또는 비밀번호 불일치")
                    return self._html(self._login_html("계정 또는 비밀번호가 맞지 않습니다", local=True), HTTPStatus.UNAUTHORIZED)
                if self.api.auth_conf["portal"]["method"] != "ldap":
                    return self._html(self._login_html("이 서버는 통합 로그인(SSO)으로만 로그인합니다"), HTTPStatus.BAD_REQUEST)
                try:
                    info = authmod.ldap_login(self.api.auth_conf, login, g("password"))
                    usr = self.api.auth.portal_user(login, self.api.auth_conf, info["name"], info["dept"], info["email"], info["groups"], "ldap")
                except authmod.AuthError as e:
                    self._failed(login, "ldap", str(e))
                    return self._html(self._login_html(html_escape(str(e))), HTTPStatus.UNAUTHORIZED)
                return self._start_session(usr, "ldap")
            pw = g("password")
            ok_pw = pw_ok(pw, self.password) if self.password else False
            if ok_pw is None:   # 8차 ⑪ · GPT 64차: 서버가 확인하지 못함 — 거절하되 실패로 세지 않는다
                return self._html(self._login_html("서버가 지금 비밀번호를 확인하지 못했습니다 — 잠시 뒤 다시 하십시오(관리자: 서버 기록 확인)"),
                                  HTTPStatus.SERVICE_UNAVAILABLE)
            if ok_pw:
                tok = secrets.token_hex(16)
                self._sessions.add(tok)
                secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""  # nginx TLS 종단 시
                return self._html("", HTTPStatus.FOUND, {"Location": "/", "Set-Cookie": f"lt_session={tok}; Path=/; HttpOnly; SameSite=Strict{secure}"})
            self._failed("(공용)", "password", "비밀번호 불일치")
            return self._html(self._login_html("비밀번호가 맞지 않습니다"), HTTPStatus.UNAUTHORIZED)
        if u.path == "/setup":
            with _SETUP_LOCK:      # 동시에 들어온 요청이 각각 계정을 만들지 않도록 한 번에 하나만
                return self._do_setup(length)
        if u.path == "/recover":
            if not self._local_login():
                return self._reject_json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
            if not 0 < length <= 4096:
                return self._reject_json({"error": "요청 크기 오류"}, HTTPStatus.BAD_REQUEST)
            body = urllib.parse.parse_qs(self._body(length).decode("utf-8", "replace"))
            g = lambda k: (body.get(k) or [""])[0]
            email = g("email").strip()
            if self._too_many("recover|" + email.lower()[:48]):
                return self._html(self._login_html("재설정 시도가 많아 5분 동안 막았습니다 — 잠시 후 다시 하십시오",
                                                   self._recover_form(email), title="비밀번호 재설정", sub=""), HTTPStatus.TOO_MANY_REQUESTS)
            try:
                if g("new") != g("confirm"):
                    raise authmod.AuthError("새 비밀번호 두 칸이 서로 다릅니다")
                self.api.accounts.reset_with_code(email, g("code"), g("new"), self._ip())
            except (authmod.AuthError, ValueError) as e:
                self._failed(email[:64], "recover", str(e))
                return self._html(self._login_html(html_escape(str(e)), self._recover_form(email), title="비밀번호 재설정",
                                                   sub="관리자가 발급한 재설정 코드로 새 비밀번호를 정합니다", art="key"), HTTPStatus.BAD_REQUEST)
            return self._html(self._login_html('<div class="ok">비밀번호를 바꿨습니다 — 새 비밀번호로 로그인하십시오</div>',
                                               self._login_form(), title="LogTriage 로그인", sub="비밀번호 재설정 완료"))
        if u.path == "/join":
            return self._do_join(length)
        if u.path == "/password":
            if not self._local_login():
                return self._reject_json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
            if self._user() is None:
                return self._reject_json({"error": "로그인이 필요합니다"}, HTTPStatus.UNAUTHORIZED)
            if not 0 < length <= 4096:
                return self._reject_json({"error": "요청 크기 오류"}, HTTPStatus.BAD_REQUEST)
            body = urllib.parse.parse_qs(self._body(length).decode("utf-8", "replace"))
            g = lambda k: (body.get(k) or [""])[0]
            if not self._form_token_ok(g("t")):
                return self._csrf_refused()
            login = self._u["login"]
            try:
                if g("new") != g("confirm"):
                    raise authmod.AuthError("새 비밀번호 두 칸이 서로 다릅니다")
                self.api.accounts.set_password(login, g("new"), old=g("current"), actor=login)
            except authmod.AuthError as e:
                self._audit("password.fail", login, str(e), ok=False)
                return self._html(self._login_html(html_escape(str(e)), self._password_form("", str(e)), title="비밀번호 변경",
                                                   sub=html_escape(login)), HTTPStatus.BAD_REQUEST)
            except ValueError as e:
                return self._html(self._login_html(html_escape(str(e)), self._password_form(), title="비밀번호 변경",
                                                   sub=html_escape(login)), HTTPStatus.BAD_REQUEST)
            usr = self.api.auth.get_user(login)
            self._audit("password.change", login)
            return self._start_session(usr, "email", "/")
        if u.path == "/api/nms/metrics":  # 원격 에이전트 푸시 — 로그인 대신 에이전트 토큰
            return self._agent_push(length)
        if u.path == "/agent/enroll":     # 19차 간편 설치 — 로그인 대신 1회용 등록 코드
            return self._agent_enroll(length)
        if u.path == "/api/hub/ingest":   # 사이트 서버 → 본사 — 로그인 대신 사이트 토큰
            return self._hub_ingest(length)
        if self._guard("POST", u.path):
            return None
        if u.path == "/access-request":
            # 막힌 화면의 폼이 보내는 요청(대본 없음). 교차 출처는 위에서 이미 걸렀다.
            if not 0 < length <= 4096:
                return self._reject_json({"error": "요청 크기 오류"}, HTTPStatus.BAD_REQUEST)
            body = urllib.parse.parse_qs(self._body(length).decode("utf-8", "replace"))
            g = lambda k: (body.get(k) or [""])[0]
            if not self._form_token_ok(g("t")):
                return self._csrf_refused()
            if not self._can_request():
                return self._html(self._notice_html("승인 요청을 쓸 수 없습니다",
                                                    "이 서버의 로그인 방식에서는 계정별 권한이 없습니다"),
                                  HTTPStatus.BAD_REQUEST)
            try:
                res = self.api.auth.request_access((self._u or {}).get("login", ""), g("kind"), g("want"),
                                                   g("action"), g("reason"), self._ip())
            except ValueError as e:
                return self._html(self._notice_html("승인 요청을 보내지 못했습니다", str(e)), HTTPStatus.BAD_REQUEST)
            self._audit("access.request", f"{res['kind']}:{res['want']}")
            what = (authmod.ROLE_KO.get(res["want"], res["want"]) + " 권한" if res["kind"] == "role"
                    else authmod.AuthStore.REQ_KO.get(res["kind"], res["kind"]) + " · " + res["want"])
            return self._html(self._notice_html(
                "승인 요청을 보냈습니다",
                f"관리자가 승인하면 다시 로그인한 뒤에 쓸 수 있습니다. 요청한 것: {what}"))
        if u.path == "/api/access/request":
            # 막힌 사람이 보내는 요청 — 조회 권한으로도 보낼 수 있다(_need 에서 viewer).
            try:
                v = self._json_body(length, 2048)
                if not self._can_request():
                    return self._json({"error": "이 서버의 로그인 방식에서는 승인 요청을 쓸 수 없습니다"},
                                      HTTPStatus.BAD_REQUEST)
                res = self.api.auth.request_access((self._u or {}).get("login", ""), str(v.get("kind", "")),
                                                   str(v.get("want", "")), str(v.get("action", "")),
                                                   str(v.get("reason", "")), self._ip())
            except ValueError as e:
                return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
            self._audit("access.request", f"{res['kind']}:{res['want']}")
            return self._json(res)
        name = u.path[5:] if u.path.startswith("/api/") else u.path
        if name not in READ_APIS or name in AUDIT_READ:
            self._audit("POST " + (name if name in API_NAMES else u.path))
        if u.path.startswith("/api/admin/") or u.path.startswith("/api/hub/"):
            return self._admin_post(u, length)
        if u.path.startswith("/api/automation/"):
            try:
                if not 0 < length <= 32768:
                    raise ValueError("작업 설정 요청 크기 오류")
                value = json.loads(self.rfile.read(length))
                if not isinstance(value, dict):
                    raise ValueError("JSON 객체 필요")
                value.pop("_actor", None)            # 행위자는 화면이 아니라 서버가 적는다
                if u.path.endswith("/purge_uploads"):
                    value["_actor"] = str((self._u or {}).get("login") or "")
                    if getattr(self.api, "auth", None):
                        self.api.auth.audit(value["_actor"], self._ip(), "uploads.purge", f"older_days={value.get('older_days', 7)}")
                if value.get("kind") == "asset_sync" and not authmod.asset_allowed(self._u, self._local_site()):
                    return self._json({"error": "자원 문서 동기화는 이 사이트 자산 조회 권한이 있는 담당자만 등록할 수 있습니다"}, HTTPStatus.FORBIDDEN)
                return self._json(self.api.automation.command(u.path.rsplit('/',1)[-1], value))
            except (ValueError, TypeError, KeyError) as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            except sqlite3.OperationalError as exc:   # database is locked/busy
                sys.stderr.write(f"[automation] sqlite {exc}\n")
                return self._json({"error": "다른 작업이 처리 중입니다 — 잠시 후 다시 시도하십시오"}, HTTPStatus.SERVICE_UNAVAILABLE)
            except Exception as exc:   # r2: 응답 없이 연결이 끊기지 않게(스택 추적은 서버 로그에만)
                sys.stderr.write(f"[automation] {type(exc).__name__}: {exc}\n")
                return self._json({"error": "자동화 처리 오류: 서버 로그 확인"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        if u.path.startswith("/api/board/"):
            return self._board_post(u, length)
        if u.path.startswith("/api/nms/"):
            return self._nms_post(u, length)
        if u.path.startswith("/api/inventory/"):
            return self._inventory_post(u, length)
        if u.path == "/api/rulepack":
            return self._rulepack(length)
        if u.path.startswith("/api/"):
            name = u.path[5:]
            # 남의 사이트의 폼이 관리자 쿠키로 우리 API 를 부르지 못하게 —
            # form 은 사용자 정의 헤더를 못 붙이고 JSON 형식으로도 못 보낸다(GPT 10차 상).
            ct = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if self.headers.get("X-NMS-Request") != "1" or ct != "application/json":
                return self._reject_json(
                    {"error": "이 요청은 우리 화면에서 보낸 것이 아닙니다"
                              " — 화면을 새로 고친 뒤 다시 해 주십시오"},
                    HTTPStatus.FORBIDDEN)
            if name not in API_NAMES:
                return self._json({"error": f"unknown api {name}"}, HTTPStatus.NOT_FOUND)
            raw = self.rfile.read(length) if length else b"[]"
            try:
                args = json.loads(raw.decode("utf-8", "replace") or "[]")
                if not isinstance(args, list):
                    args = [args]
                actor = getattr(self.api, "actor", None)
                if actor is not None:
                    actor.login = (self._u or {}).get("login", "")
                    actor.name = (self._u or {}).get("name", "")
                    actor.role = (self._u or {}).get("role", "")
                if name == "generate_report" and not (args and isinstance(args[0], str) and args[0].strip()):
                    # 분석 ID 없이 부르면 '가장 최근 분석' — 누구 것이든 맨 앞이 아니라 이 계정이 쓸 수 있는 가장 최근 것(10-23)
                    usable = self._usable_history()
                    if not usable:
                        return self._json({"error": "보고서를 만들 분석 건이 없습니다 — 먼저 분석을 실행하십시오."})
                    args = [usable[0].get("id", "")] + list(args[1:])
                blocked = self._other_owner(name, args)
                if blocked:
                    return self._json(blocked, HTTPStatus.FORBIDDEN)
                if name == "quickfind":
                    # 가린 뒤에 거른다 — 가리기 전에 거르면 남의 분석의 호스트명으로도 걸려 '있다는 것' 이 새어 나간다(GPT UI 19차)
                    # 화면의 0.18초 늦추기는 직접 호출을 못 막는다 — 계정마다 10초에 30번까지(GPT 19차 후속 권고: 무제한 자원 사용)
                    from .gui.app import quickfind_rows
                    me = (self._u or {}).get("login", "") or self.client_address[0]
                    if not _qf_allow(me):
                        # 빈 결과로 보내면 '찾는 것이 없다' 로 오해한다 — 429 와 따로 된 말(GPT 20차)
                        return self._json({"error": "찾기 요청이 너무 잦습니다 — 잠시 뒤 다시 입력해 주십시오", "rate_limited": True},
                                          HTTPStatus.TOO_MANY_REQUESTS)
                    else:
                        res = quickfind_rows(privacy.mask_for_viewer(self.api.history(), (self._u or {}).get("login", "")),
                                             args[0] if args else "")
                elif name in ("custom_form_preview", "custom_form_analyze"):
                    res = getattr(self.api, name)(*args, _hist=self._usable_history())   # 예시·미리보기 = 쓸 수 있는 가장 최근 분석(10-23)
                elif name == "diag":   # 22차: 평문 접속이면 환경 점검 띠 맨 위에(요청을 아는 곳은 여기뿐)
                    res = self.api.diag()
                    if isinstance(res, dict) and self._plaintext_lan():
                        it = {"code": "plaintext_http", "text": self.PLAINTEXT_WARN, "action": "",
                              "clears": "https:// 주소로 접속하면(서버에 HTTPS 를 켠 뒤)"}
                        res["warn_items"] = [it] + list(res.get("warn_items") or [])
                        res["warnings"] = [it["text"]] + list(res.get("warnings") or [])
                elif name == "stats":
                    # 전체 현황은 이력을 모아 만든다 — 가린 이력으로 모아야 '최근 분석'·TOP5 조치·날짜별 판정에 다른 부서 원본이 안 섞인다(10-23)
                    res = self.api.stats(*args, _hist=privacy.mask_for_viewer(self.api.history(), (self._u or {}).get("login", ""),
                                                                              shares=self._same_dept))
                else:
                    res = getattr(self.api, name)(*args)
                    res = self._mask_history(name, res, args)
                    if name == "home":
                        res = self._mask_home(res)
                    if name == "report_profile_sources" and isinstance(res, dict):   # 19차: 볼 수 있는 분석의 저장값만 후보로
                        res["incidents"] = [x for x in res.get("incidents") or [] if self._can_use_incident(str(x.get("id") or ""))]
            except (ValueError, authmod.AuthError) as e:
                # 우리가 **일부러 띄운 말** — 사용자가 읽고 고칠 수 있는 안내다. 그대로 보낸다.
                res = {"error": str(e)}
            except Exception as e:
                # 예상 못 한 것은 **그대로 돌려주지 않는다.** 전에는 파이썬 예외 글을 그대로
                # 보냈고, 거기에 내부 클래스·메서드 이름과 인자 개수까지 실려 나갔다
                #   "TypeError: ServerApi.asset_fields() takes 1 positional argument but 2 were given"
                # 경로·SQL 이 실릴 수도 있다. 자세한 것은 서버 기록으로만 남긴다.
                sys.stderr.write(f"[api] {name} {type(e).__name__}: {e}" + chr(10))
                res = {"error": "요청을 처리하지 못했습니다 — 보낸 값을 확인해 주십시오."
                                " 자세한 내용은 서버 기록에 남았습니다"}
            return self._json(res)
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_PUT(self):
        u = urllib.parse.urlsplit(self.path)
        if not self._begin():
            return None
        if not self._same_origin():
            return self._reject_json({"error": "다른 출처(Origin)의 요청은 허용하지 않습니다"}, HTTPStatus.FORBIDDEN)
        if u.path == "/api/hub/file":   # 사이트 서버 → 본사 보고서 사본 — 사이트 토큰
            return self._hub_file_put(u)
        if self._guard("PUT", u.path):
            return None
        self._audit("PUT " + u.path)
        if u.path != "/api/upload":
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        length = int(self.headers.get("Content-Length") or 0)
        name = (urllib.parse.parse_qs(u.query).get("name") or ["upload.log"])[0]
        if length <= 0:
            return self._json({"error": "빈 파일"})
        if length > MAX_UPLOAD:
            return self._json({"error": f"파일이 너무 큽니다({length // 1024 // 1024}MB) — 1회 600MB 이하로 장애 시각 전후 구간만 잘라서 올려 주십시오"})
        if not _ACTIVE.acquire(blocking=False):
            return self._json({"error": f"동시 처리 한도({MAX_ACTIVE}건) 초과 — 잠시 후 다시 올려 주십시오"})
        try:
            return self._json(self.api.save_upload(name, self.rfile, length))
        except Exception as e:
            return self._json({"error": str(e)})
        finally:
            _ACTIVE.release()

    # ── 전사: 사용자 정보·포털 SSO·본사 허브·관리(r4) ──
    def _me(self) -> dict:
        u = self._u or {}
        hc, ac = self.api.hub_conf, self.api.auth_conf
        lvl = authmod.ROLES.get(u.get("role"), 0)
        if self._local_login():
            how = "email"
        elif self._portal():
            how = "portal:" + ac["portal"]["method"]
        else:
            how = "password" if self.password else ("desktop" if self.desktop else "none")
        return {"login": u.get("login"), "name": u.get("name"), "dept": u.get("dept", ""), "role": u.get("role"),
                "role_ko": authmod.ROLE_KO.get(u.get("role"), ""), "sites": u.get("sites", []), "source": u.get("source"),
                "auth": how, "logout": how.startswith("portal") or how in ("password", "email"),
                "email_domain": self._domain() if self._local_login() else None,
                "must_change": self._must_change(),
                "site": {"id": hc["site_id"], "name": hc.get("site_name"), "role": hc["role"]} if hc else None,
                "hub": (hc or {}).get("role"), "can_operate": lvl >= 2, "is_admin": lvl >= 3,
                "asset_sites": u.get("asset_sites", []), "can_assets": authmod.asset_allowed(u, self._local_site())}

    def _sso(self, u):
        conf = self.api.auth_conf
        if not self._portal():
            return self._json({"error": "통합 로그인 연동이 설정되지 않았습니다"}, HTTPStatus.NOT_FOUND)
        method = conf["portal"]["method"]
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path == "/sso/oidc/start" and method == "oidc":
                return self._html("", HTTPStatus.FOUND, {"Location": self.api.oidc.authorize_url()})
            if u.path == "/sso/oidc/callback" and method == "oidc":
                if self._too_many("(oidc)"):
                    raise authmod.AuthError("로그인 실패가 많아 5분 동안 막았습니다")
                info = self.api.oidc.callback(q)
            elif u.path == "/sso/link" and method == "link":
                if self._too_many((q.get("u") or [""])[0]):
                    raise authmod.AuthError("로그인 실패가 많아 5분 동안 막았습니다")
                info = authmod.link_login(conf, q, self.api.auth)
            else:
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            usr = self.api.auth.portal_user(info["login"], conf, info["name"], info["dept"], info["email"], info["groups"], method)
        except authmod.AuthError as e:
            self._failed((q.get("u") or [""])[0], method, str(e))
            return self._html(self._login_html(html_escape(str(e))), HTTPStatus.UNAUTHORIZED)
        except (KeyError, ValueError) as e:
            sys.stderr.write(f"[sso] {type(e).__name__}: {e}\n")
            return self._html(self._login_html("통합 로그인 설정 오류 — 관리자에게 문의하십시오"), HTTPStatus.INTERNAL_SERVER_ERROR)
        nxt = (q.get("next") or ["/"])[0]   # 포털 메뉴가 특정 화면으로 바로 보낼 때(같은 서버 경로만)
        if not re.fullmatch(r"/[A-Za-z0-9_\-/#?=&.%]*", nxt) or nxt.startswith("//"):
            nxt = "/"
        return self._start_session(usr, method, nxt)

    def _json_body(self, length: int, limit: int = 32768) -> dict:
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            raise ValueError("Content-Type: application/json 이 필요합니다")
        if not 0 < length <= limit:
            raise ValueError("요청 크기 오류")
        v = json.loads(self.rfile.read(length))
        if not isinstance(v, dict):
            raise ValueError("JSON 객체가 필요합니다")
        return v

    _hub_slots = threading.BoundedSemaphore(4)     # 본사 요약 수신 동시 4건
    _hub_file_slots = threading.BoundedSemaphore(2)  # 본사 보고서 사본 수신 동시 2건
    _hub_last: dict = {}                            # 사이트별 마지막 요약 수신 시각

    def _hub_ingest(self, length: int):
        hub = self.api.hub
        if hub is None:
            return self._reject_json({"error": "이 서버는 본사(central) 서버가 아닙니다"}, HTTPStatus.NOT_FOUND)
        site = hub.site_by_token(self.headers.get("X-Site-Token", ""))
        if not site:
            self.api.auth.audit("site:" + self.headers.get("X-Site-Id", "?")[:32], self._ip(), "hub.denied", "ingest", ok=False)
            return self._reject_json({"error": "사이트 토큰이 맞지 않거나 사용 중지된 사이트입니다"}, HTTPStatus.UNAUTHORIZED)
        now = time.time()
        if now - self._hub_last.get(site["id"], 0) < hubmod.INGEST_MIN_GAP:
            return self._reject_json({"error": "전송 간격이 너무 짧습니다"}, HTTPStatus.TOO_MANY_REQUESTS)
        lock = hub.site_lock(site["id"])
        if not lock.acquire(blocking=False):
            return self._reject_json({"error": "같은 사이트의 전송을 처리 중입니다"}, HTTPStatus.TOO_MANY_REQUESTS)
        if not self._hub_slots.acquire(blocking=False):
            lock.release()
            return self._reject_json({"error": "본사 수신이 몰려 있습니다 — 다음 주기에 다시 보냅니다"}, HTTPStatus.TOO_MANY_REQUESTS)
        try:
            if not 0 < length <= hubmod.MAX_INGEST:
                raise ValueError("전송 크기 오류(8MB 이하)")
            self._hub_last[site["id"]] = now
            return self._json(hub.ingest(site["id"], json.loads(self.rfile.read(length)), self._ip()))
        except hubmod.ReplayError as e:
            self.api.auth.audit("site:" + site["id"], self._ip(), "hub.replay", "ingest", str(e), ok=False)
            return self._json({"error": str(e)}, HTTPStatus.CONFLICT)
        except (ValueError, TypeError, RecursionError) as e:
            return self._json({"error": str(e)[:300]}, HTTPStatus.BAD_REQUEST)
        except Exception as e:
            sys.stderr.write(f"[hub] ingest {type(e).__name__}: {e}\n")
            return self._json({"error": "본사 저장 오류: 서버 로그 확인"}, HTTPStatus.INTERNAL_SERVER_ERROR)
        finally:
            self._hub_slots.release(); lock.release()

    def _hub_file_put(self, u):
        hub = self.api.hub
        if hub is None:
            return self._reject_json({"error": "이 서버는 본사(central) 서버가 아닙니다"}, HTTPStatus.NOT_FOUND)
        site = hub.site_by_token(self.headers.get("X-Site-Token", ""))
        if not site:
            return self._reject_json({"error": "사이트 토큰이 맞지 않거나 사용 중지된 사이트입니다"}, HTTPStatus.UNAUTHORIZED)
        q = urllib.parse.parse_qs(u.query)
        length = int(self.headers.get("Content-Length") or 0)
        lock = hub.site_lock("file:" + site["id"])   # 사이트별 파일 쓰기 직렬화(같은 이름 경쟁 방지)
        if not lock.acquire(blocking=False):
            return self._reject_json({"error": "같은 사이트의 보고서를 받는 중입니다"}, HTTPStatus.TOO_MANY_REQUESTS)
        if not self._hub_file_slots.acquire(blocking=False):
            lock.release()
            return self._reject_json({"error": "본사 수신이 몰려 있습니다 — 다음 주기에 다시 보냅니다"}, HTTPStatus.TOO_MANY_REQUESTS)
        try:
            mt = float((q.get("mtime") or ["0"])[0])
            if not (0 <= mt <= time.time() + 86400):   # NaN·무한대·먼 미래 시각은 수신 시각으로
                mt = time.time()
            return self._json(hub.save_file(site["id"], (q.get("name") or [""])[0], mt, self.rfile, length))
        except hubmod.ConflictError as e:
            return self._json({"error": str(e)}, HTTPStatus.CONFLICT)
        except hubmod.QuotaError as e:
            self.close_connection = True
            return self._json({"error": str(e)}, HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        except ValueError as e:
            self.close_connection = True
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        finally:
            self._hub_file_slots.release(); lock.release()

    def _do_join(self, length: int):
        """계정 직접 만들기(POST /join) — 가입 방식에 따라 승인 대기 또는 바로 사용."""
        if not self._local_login():
            return self._reject_json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
        if self._needs_setup():
            return self._reject_json({"error": "아직 계정이 없습니다 — 먼저 관리자 계정을 만드십시오(/setup)"},
                                     HTTPStatus.FORBIDDEN)
        if self.api.accounts.conf["signup"] == "off":
            return self._reject_json({"error": "이 서버는 직접 가입을 받지 않습니다"}, HTTPStatus.FORBIDDEN)
        if not 0 < length <= 4096:
            return self._reject_json({"error": "요청 크기 오류"}, HTTPStatus.BAD_REQUEST)
        body = urllib.parse.parse_qs(self._body(length).decode("utf-8", "replace"))
        g = lambda k: (body.get(k) or [""])[0]
        email, name, dept = g("email").strip(), g("name").strip()[:40], g("dept").strip()[:40]
        # 훑어 보는 것을 막는다 — 같은 IP 로 ID 를 바꿔 가며 '있는 계정' 을 찾아낼 수 없게.
        if self._too_many("join|" + email.lower()[:48]):
            return self._html(self._login_html("가입 시도가 많아 5분 동안 막았습니다 — 잠시 후 다시 하십시오",
                                               self._join_form(email, name, dept), title="계정 만들기",
                                               sub="회사 이메일로 본인 계정을 만듭니다", art="key"),
                              HTTPStatus.TOO_MANY_REQUESTS)
        try:
            if g("password") != g("confirm"):
                raise authmod.AuthError("비밀번호 두 칸이 서로 다릅니다")
            r = self.api.accounts.signup(email, g("password"), name, dept, g("code"), self._ip())
        except (authmod.AuthError, ValueError) as e:
            self._failed(email[:64], "join", str(e))
            return self._html(self._login_html(html_escape(str(e)), self._join_form(email, name, dept),
                                               title="계정 만들기", sub="회사 이메일로 본인 계정을 만듭니다",
                                               art="key"), HTTPStatus.BAD_REQUEST)
        if r["pending"]:
            return self._html(self._login_html(
                '<div class="ok">가입 신청을 접수했습니다 — 관리자 승인 뒤에 로그인할 수 있습니다</div>',
                '<p class="note">관리자가 [사용자 · 권한] 화면의 <b>[계정 · 가입]</b> 에서 승인하면 바로 쓸 수 '
                '있습니다. 급하면 담당자에게 승인을 요청하십시오.</p><a class="btn" href="/login">로그인 화면</a>',
                title="가입 신청 접수", sub=html_escape(r["email"])))
        return self._html(self._login_html(
            '<div class="ok">계정을 만들었습니다 — 새 비밀번호로 로그인하십시오</div>',
            self._login_form(), title="LogTriage 로그인", sub=html_escape(r["email"])))

    def _do_setup(self, length: int):
        """첫 관리자 계정 만들기(POST /setup) — 허용 범위 확인 → 계정 생성 → 초기 설정 화면·코드 닫기."""
        if not self._local_login() or not self._needs_setup():
            return self._reject_json({"error": "이미 계정이 있습니다"}, HTTPStatus.FORBIDDEN)
        if not 0 < length <= 4096:
            return self._reject_json({"error": "요청 크기 오류"}, HTTPStatus.BAD_REQUEST)
        body = urllib.parse.parse_qs(self._body(length).decode("utf-8", "replace"))
        g = lambda k: (body.get(k) or [""])[0]
        if not self._setup_ok(g("t")):
            # 72비트라 맞힐 수 없지만, **세지 않는 것**과 못 맞히는 것은 다르다.
            self._failed("(setup)", "setup", "초기 설정 코드 불일치")
            return self._reject_json({"error": "초기 설정 코드가 필요합니다"}, HTTPStatus.FORBIDDEN)
        if self._too_many("(setup)"):
            return self._html(self._login_html("시도가 많아 5분 동안 막았습니다 — 잠시 후 다시 하십시오", self._setup_form(g("t")),
                                               title="관리자 계정 만들기", sub="처음 기동", art="key"), HTTPStatus.TOO_MANY_REQUESTS)
        email = ((self.api.auth_conf or {}).get("first_admin") or g("email")).strip()   # 예약된 첫 관리자가 있으면 그 ID 로 고정
        try:
            if g("password") != g("confirm"):
                raise authmod.AuthError("비밀번호 두 칸이 서로 다릅니다")
            site = self._local_site()
            self.api.accounts.create(email, g("password"), "admin", ["*"], [site] if site else [],
                                     g("name").strip()[:40], "", actor="(초기 설정)", must_change=False)
        except (authmod.AuthError, ValueError) as e:
            self._failed(email[:64], "setup", str(e))
            return self._html(self._login_html(html_escape(str(e)), self._setup_form(g("t")), title="관리자 계정 만들기",
                                               sub="처음 기동 — 이 서버를 쓸 첫 계정을 등록합니다", art="key"), HTTPStatus.BAD_REQUEST)
        self.api.setup_close()           # 초기 설정 화면·코드는 여기서 닫힌다
        usr = self.api.auth.get_user(self.api.accounts.list_one(email.lower())["email"])
        self.api.auth.audit(usr["login"], self._ip(), "account.setup", usr["login"], "첫 관리자 계정")
        return self._start_session(usr, "email", "/")

    def _board_post(self, u, length: int):
        """게시판 쓰기 — 글·답글·채택·삭제. 조회 권한(viewer)도 질문·답글은 쓸 수 있게 한다."""
        b, me = self.api.board, (self._u or {})      # 로그인 없는 설정(mode=off)에서도 터지지 않게
        try:
            v = self._json_body(length)
            op = u.path.rsplit("/", 1)[-1]
            if op == "create":
                res = b.create(me, str(v.get("kind", "question")), str(v.get("title", "")), str(v.get("body", "")),
                               v.get("incidents") or [], bool(v.get("share_raw")), self._local_site())
                self._audit("board.create", str(res.get("id")), str(v.get("title", ""))[:60])
            elif op == "update":
                res = b.update(me, int(v.get("id", 0)), **{k: v[k] for k in ("kind", "title", "body", "incidents", "share_raw", "solved") if k in v})
                self._audit("board.update", str(v.get("id")))
            elif op == "delete":
                res = b.delete(me, int(v.get("id", 0)), is_admin=(me.get("role") == "admin"))
                self._audit("board.delete", str(v.get("id")))
            elif op == "reply":
                res = b.reply(me, int(v.get("id", 0)), str(v.get("body", "")))
                self._audit("board.reply", str(v.get("id")))
            elif op == "accept":
                res = b.accept(me, int(v.get("id", 0)), int(v.get("reply", 0)))
            elif op == "reply_delete":
                res = b.delete_reply(me, int(v.get("reply", 0)), is_admin=(me.get("role") == "admin"))
            else:
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return self._json(res)
        except (BoardError, ValueError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)

    def _board_get(self, u):
        q = urllib.parse.parse_qs(u.query)
        one = lambda k, d="": (q.get(k) or [d])[0]
        b = self.api.board
        try:
            if u.path == "/api/board/list":
                return self._json(b.list(one("kind"), one("q"), one("mine"), int(one("limit", "100") or 100),
                                         int(one("offset", "0") or 0)))
            if u.path == "/api/board/post":
                d = b.get(int(one("id", "0") or 0))
                d["attached"] = self._board_attached(d)      # 붙인 분석의 이름·시각(가림 규칙 그대로)
                return self._json(d)
            if u.path == "/api/board/incident":
                return self._json(self._board_incident(int(one("post", "0") or 0), one("id")))
            if u.path == "/api/board/mine":     # 글에 붙일 수 있는 내 분석 이력
                me = (self._u or {}).get("login", "")
                rows = [h for h in self.api.store.history() if privacy.owner_of(h) == me or not privacy.owner_of(h)
                        or self._same_dept(privacy.owner_of(h))]   # 15차: 같은 부서 분석도 붙일 수 있다
                return self._json({"incidents": [{"id": h.get("id"), "name": h.get("name", ""),
                                                  "at": h.get("analyzed_at", ""), "mine": privacy.owner_of(h) == me}
                                                 for h in rows[:200]]})
        except (BoardError, ValueError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _board_attached(self, post: dict) -> list:
        """글에 붙은 분석 이력의 이름·시각 — 목록에서 무엇인지 보이게. 이름에 호스트가 섞여 있을 수 있어 같은 규칙으로 가린다."""
        me = (self._u or {}).get("login", "")
        out = []
        for i in (post.get("incidents") or []):
            inc = self.api.store.get(i)
            if not inc:
                out.append({"id": i, "name": "", "at": "", "gone": True, "mine": False})
                continue
            owner = privacy.owner_of(inc)
            shared = bool(post.get("share_raw")) and owner and owner == post.get("author")
            raw = bool(owner and (owner == me or shared or self._same_dept(owner)))
            name = inc.get("name", "") or ""
            out.append({"id": i, "name": name if raw else privacy.mask_text(name, privacy.hosts_of(inc)),
                        "at": inc.get("analyzed_at", ""), "gone": False, "mine": bool(owner and owner == me),
                        "masked": not raw})
        return out

    def _board_incident(self, post_id: int, inc_id: str) -> dict:
        """글에 붙은 분석 이력 열기 — 본인 것이면 원문, 아니면 IP·호스트명을 가린 사본.
        글쓴이가 '원문 공개'를 켜 둔 글에서는 그 글쓴이가 등록한 분석에 한해 원문을 보여 준다."""
        post = self.api.board.get(post_id, bump=False)
        if inc_id not in (post.get("incidents") or []):
            raise BoardError("이 글에 붙어 있지 않은 분석입니다")
        inc = self.api.store.get(inc_id)
        if not inc:
            raise BoardError("분석 이력을 찾을 수 없습니다(보관 기간이 지났을 수 있습니다)")
        me = (self._u or {}).get("login", "")
        owner = privacy.owner_of(inc)
        shared = bool(post.get("share_raw")) and owner and owner == post.get("author")
        if owner and (owner == me or shared or self._same_dept(owner)):   # 15차: 같은 부서는 원본
            out = dict(inc)
            out["masked"] = False
        else:
            out = privacy.mask_result(inc)
        res = self.api.store.search_events(inc_id, "", "", "", 50)   # 결과는 dict — rows 또는 error
        note = str(res.get("error") or "") if isinstance(res, dict) else ""
        rows = list(res.get("rows") or []) if isinstance(res, dict) else list(res or [])
        if rows and out.get("masked"):
            rows = privacy.mask_value(rows, privacy.hosts_of(inc))
        if not rows:
            rows = out.get("events") or []        # 이벤트 원본 보관이 끝난 건은 결과 안의 목록(이미 같은 규칙으로 가려져 있다)
            if rows:
                note = ""
        return {"incident": out, "events": rows, "note": note, "shared": bool(shared),
                "total": int(res.get("total", len(rows))) if isinstance(res, dict) else len(rows),
                "owner_name": inc.get("owner_name", ""), "can_open": bool(owner and (owner == me or self._same_dept(owner)))}

    def _hub_get(self, u):
        q = urllib.parse.parse_qs(u.query)
        hub, hc = self.api.hub, self.api.hub_conf
        allowed = self._u.get("sites") or []
        if u.path == "/api/hub/mode":
            # 지금 이 서버가 어떤 모드인지. **사이트 토큰은 내려보내지 않는다** —
            # 화면을 볼 수 있는 사람이 곧 본사에 쓸 수 있는 사람이 되면 안 된다
            # 허용 목록도 함께 준다 — 화면이 "아무 데나 보낼 수 있는 상태" 인지 말할 수 있게
            mode = hubmod.public_conf(self.api.hub_conf, hubmod.trusted(self.api._base))
            # 서버가 막는 기준과 **같은 값**을 내려보낸다 — 화면이 다른 기준으로 잠그면
            # "칸은 열렸는데 거절당한다" 가 생긴다
            mode["locked_site_id"] = hubmod.locked_site(self.api._base)
            # 로그인이 없고 허용 목록도 없으면 사이트 모드를 켤 수 없다 — 화면이 미리 말한다
            mode["no_login"] = not (self.api.auth_conf and self.api.auth_conf["mode"] != "off") \
                and not self.password
            mode["site_blocked"] = bool(mode["no_login"] and not mode["allow_list"])
            # 지난번 모드 변경이 어긋난 채로 남아 있으면 **화면이 크게 말한다**(GPT 중상).
            # 서버 기록에만 적어 두면 아무도 안 본다 — 그 사이 본사 전송은 멈춰 있다.
            mode["broken"] = self.api.hub_broken()
            # **단독과 '차단' 을 구분해서 보여 준다** — 같은 none 으로 두면 멈춘 것을 모른다
            mode["hub_state"] = self.api.hub_state()
            _rec = self.api.hub_recovery()
            mode["broken_reason"] = str(_rec.get("reason") or "")
            mode["broken_at"] = _rec.get("at") or 0
            return self._json({"mode": mode,
                               "can_change": authmod.ROLES.get(self._u.get("role"), 0) >= 3})
        if u.path == "/api/hub/overview":
            client = self.api.hub_client.status() if self.api.hub_client else None
            if hub is None:
                return self._json({"role": hc["role"] if hc else "none", "client": client,
                                   "site": {"id": hc["site_id"], "name": hc.get("site_name")} if hc else None})
            data = hub.overview(allowed)
            try:   # 본사 자신의 서식(기준) — 사이트 원장과 같은 표에서 대조
                from .report_custom import ledger_export
                data["hq_forms"] = [{k: f.get(k) for k in ("kind", "name", "sha256")} for f in ledger_export(self.api._base / "report-template")["forms"]]
            except Exception:   # noqa: BLE001
                data["hq_forms"] = []
            assets = set(self._u.get("asset_sites") or []) if self._u.get("source") != "legacy" else None
            for key in ("down", "hot", "alerts"):   # 장비 주소(IP)는 자산 정보 — 자산 조회 사이트만 표시
                for r in data[key]:
                    if assets is not None and r["site_id"] not in assets:
                        r["address"] = "(자산 권한 필요)"
            for st in data["sites"]:
                st["can_assets"] = assets is None or st["id"] in assets
            data.update(role="central", client=client, site={"id": hc["site_id"], "name": hc.get("site_name")})
            return self._json(data)
        if hub is None:
            return self._json({"error": "본사(central) 서버에서만 제공합니다"}, HTTPStatus.NOT_FOUND)
        sid = (q.get("site") or [""])[0]
        if not authmod.site_allowed(self._u, sid):
            return self._json({"error": "이 사이트에 대한 조회 권한이 없습니다"}, HTTPStatus.FORBIDDEN)
        if u.path == "/api/hub/targets":
            if not authmod.asset_allowed(self._u, sid):
                return self._json({"error": "사이트 장비 목록(자산 현황)은 해당 사이트 담당자만 볼 수 있습니다"}, HTTPStatus.FORBIDDEN)
            self._audit("asset.view", f"hub/{sid}/targets")
            return self._json({"site": sid, "targets": hub.site_targets(sid)})
        if u.path == "/api/hub/file":
            if not authmod.asset_allowed(self._u, sid):
                return self._json({"error": "사이트 보고서 사본(장비 목록 포함)은 해당 사이트 자산 조회 권한이 있는 담당자만 내려받습니다"}, HTTPStatus.FORBIDDEN)
            name = (q.get("name") or [""])[0]
            f = hub.file_path(sid, name)
            if not f:
                return self._json({"error": "파일이 없습니다"}, HTTPStatus.NOT_FOUND)
            self._audit("download", f"hub/{sid}/{f.name}")
            return self._send_file(f.name, f.read_bytes(), "application/octet-stream")
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _admin_get(self, u):
        q = urllib.parse.parse_qs(u.query)
        a = self.api.auth
        if u.path == "/api/admin/users":
            sites = self.api.hub.sites() if self.api.hub else ([{"id": self.api.hub_conf["site_id"], "name": self.api.hub_conf.get("site_name")}] if self.api.hub_conf else [{"id": "LOCAL", "name": "이 서버(단독 설치)"}])
            return self._json({"users": a.users(), "roles": authmod.ROLE_KO, "sites": [{"id": s["id"], "name": s.get("name")} for s in sites],
                               "active_1h": a.sessions_count()})
        if u.path == "/api/admin/audit":
            g = lambda k, d="": (q.get(k) or [d])[0]
            try:
                rows = a.audit_list(int(g("limit", "300")), g("login"), g("action"), int(g("days", "30")))
            except ValueError:
                return self._json({"error": "조회 조건 오류"}, HTTPStatus.BAD_REQUEST)
            return self._json({"rows": rows})
        if u.path == "/api/admin/accounts":
            if not self.api.accounts:
                return self._json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
            from .accounts import SIGNUP
            acc = self.api.accounts
            rows = acc.list()
            for r in rows:                      # 발급해 둔 재설정 코드가 살아 있는지 함께 보여 준다
                r["code"] = acc.code_status(r["email"])
            from .accounts import SIGNUP_FROM_SCREEN
            return self._json({"accounts": rows, "domain": self._domain(), "policy": acc.conf,
                               "roles": authmod.ROLE_KO,
                               "signup": {"mode": acc.signup_mode(), "modes": SIGNUP,
                                          "screen": list(SIGNUP_FROM_SCREEN),
                                          "max_role": authmod.AuthStore.REQ_MAX_ROLE,
                                          "code": acc.signup_code_status()},
                               "pending": [r for r in rows if r["pending"]]})
        if u.path == "/api/admin/requests":
            g = lambda k, d="": (q.get(k) or [d])[0]
            return self._json({"requests": a.access_requests(g("status")), "kinds": a.REQ_KO,
                               "roles": authmod.ROLE_KO})
        if u.path == "/api/admin/tmp_backups":   # 아이디어 9: 남은 임시 백업 폴더(이름·상태·크기만)
            from .safe_backup import list_backups
            return self._json({"items": list_backups(self.api._base), "retention_days": self.api.automation.tmp_retention()})
        if u.path in ("/api/admin/link_review", "/api/admin/link_review_detail"):   # 8차 ②: 에이전트 검토 연결 승인
            from . import link_review as LR
            try:
                if u.path.endswith("_detail"):
                    g = lambda k: (q.get(k) or [""])[0]  # noqa: E731
                    return self._json(LR.detail(self.api._base, g("procedure"), g("id"), self._u["login"]))
                its = LR.items(self.api._base)
                return self._json({"items": its, "counts": {k: sum(1 for x in its if x["state"] == k) for k in ("대기", "승인", "묶음 승인", "반려")}})
            except ValueError as e:
                return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        if u.path == "/api/admin/conf":
            hc = dict(self.api.hub_conf or {})
            if hc.get("hub_token"):
                hc["hub_token"] = "●●●● (설정됨)"
            return self._json({"auth": authmod.public_conf(self.api.auth_conf), "hub": hc or {"role": "none"},
                               "legacy_password": bool(self.password), "base": str(self.api._base),
                               "sites": self.api.hub.sites() if self.api.hub else []})
        return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _admin_post(self, u, length: int):
        try:
            v = self._json_body(length)
            a, hub, me = self.api.auth, self.api.hub, self._u["login"]
            op = u.path.rsplit("/", 1)[-1]
            if u.path.startswith("/api/admin/") and op.startswith("account_"):
                if not self.api.accounts:
                    return self._json({"error": "이 서버는 이메일 계정 로그인을 쓰지 않습니다"}, HTTPStatus.NOT_FOUND)
                acc, email = self.api.accounts, str(v.get("email", ""))
                if op == "account_add":
                    res = acc.create(email, None, str(v.get("role", "viewer")), v.get("sites") or [], v.get("asset_sites") or [],
                                     str(v.get("name", "")), str(v.get("dept", "")), actor=me)
                elif op == "account_reset":
                    res = {"ok": True, "email": email, "password": acc.reset(email, actor=me)}
                elif op == "account_code":       # 비밀번호 분실 - 재설정 코드 발급(본인 확인은 관리자가 오프라인으로)
                    res = acc.issue_code(email, actor=me, minutes=int(v.get("minutes") or 0) or None)
                elif op == "account_code_cancel":
                    acc.cancel_code(email, actor=me); res = {"ok": True}
                elif op == "account_unlock":
                    acc.unlock(email, actor=me); res = {"ok": True}
                elif op == "account_approve":
                    res = acc.approve(email, actor=me, role=str(v.get("role", "viewer")),
                                      sites=v.get("sites") or [], asset_sites=v.get("asset_sites") or [])
                    self._hdr_cache.clear()
                elif op == "account_reject":
                    acc.reject(email, actor=me, why=str(v.get("why", ""))); res = {"ok": True}
                elif op == "account_signup_mode":
                    res = self.api.set_signup(str(v.get("mode", "")), actor=me)
                elif op == "account_signup_code":
                    res = acc.issue_signup_code(actor=me, minutes=int(v.get("minutes") or 0),
                                                max_uses=int(v.get("max_uses") or 0))
                elif op == "account_signup_code_cancel":
                    acc.cancel_signup_code(actor=me); res = {"ok": True}
                elif op == "account_delete":
                    if email == me:
                        raise ValueError("자기 자신은 삭제할 수 없습니다")
                    acc.delete(email, actor=me); res = {"ok": True}
                else:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                self._audit("admin." + op, email)
                return self._json(res)
            if u.path.startswith("/api/admin/"):
                if op == "tmp_backup_retention":   # 3차 아이디어 11 — 기본 0(사용 안 함)
                    try:
                        want = int(v.get("days", 0) or 0)
                    except (TypeError, ValueError):
                        want = -1
                    if want > 0:   # 7차(GPT 60·61차): 자동 삭제를 켜는 것은 '지우기 권한'을 미리 주는 일 — 지우기와 같은 재인증
                        ok, how, err = self._reauth(str(v.get("password", "")))
                        if not ok:
                            self._audit("admin.tmp_backup_retention", str(want), f"재인증 실패({how}): {err}"[:80], ok=False)
                            return self._json({"error": err}, HTTPStatus.FORBIDDEN)
                    days = self.api.automation.set_tmp_retention(v.get("days", 0))
                    self._audit("admin.tmp_backup_retention", str(days))
                    return self._json({"ok": True, "days": days})
                if op == "tmp_backup_delete":
                    from .safe_backup import QZ, delete_backup
                    name = str(v.get("name", ""))
                    how = ""
                    if name.startswith(QZ):   # 7차 아이디어 5: 격리 폴더 '지우기'는 비밀번호 재입력 — 격리(이름 바꾸기)는 그대로
                        ok, how, err = self._reauth(str(v.get("password", "")))
                        if not ok:
                            self._audit("admin.tmp_backup_delete", name[:60], f"재인증 실패({how}): {err}"[:80], ok=False)
                            return self._json({"error": err, "reauth": how != "none"}, HTTPStatus.FORBIDDEN)
                    res = delete_backup(self.api._base, name, allow_delete=bool(how) and how != "none")
                    self._audit("admin.tmp_backup_" + ("quarantine" if res.get("quarantined") else "delete"), name[:60],
                                (("재인증 " + how + " · ") if how else "") + (("지문 " + str(res.get("sha", ""))) if res.get("ok") else str(res.get("error", "")))[:80],
                                ok=bool(res.get("ok")))
                    if not res.get("ok"):
                        return self._json({"error": res.get("error", "지우지 않았습니다")}, HTTPStatus.CONFLICT)
                    return self._json(res)
                if op in ("link_review_decide", "link_review_sample", "link_review_batch"):   # 8차 ②
                    from . import link_review as LR
                    try:
                        if op == "link_review_decide":
                            try:
                                rev = int(v.get("rev"))
                            except (TypeError, ValueError):
                                rev = None
                            res = LR.decide(self.api._base, str(v.get("procedure", "")), str(v.get("id", "")), str(v.get("decision", "")),
                                            me, str(v.get("note", "")), rev=rev, answers=v.get("answers"))
                            self._audit("admin.link_review", f"{res['procedure']}|{res['id']}"[:80], res["decision"] + (" · " + res["note"] if res["note"] else ""))
                        elif op == "link_review_sample":
                            res = LR.sample(self.api._base, v.get("pairs") or [], me)
                        else:
                            res = LR.batch(self.api._base, v.get("pairs") or [], me)
                            self._audit("admin.link_review_batch", f"{res['approved']}건", "묶음 승인(개별 검토 아님 · 표본 3건 열람)")
                    except ValueError as e:
                        return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
                    return self._json(res)
                if op == "request_decide":
                    res = a.decide_request(int(v.get("id") or 0), bool(v.get("approve")), me,
                                           str(v.get("note", "")))
                    self._hdr_cache.clear()
                    self._audit("access." + ("approve" if v.get("approve") else "deny"),
                                res["login"], f"{res['kind']}:{res['want']}")
                    return self._json(res)
                if op == "user_add":
                    res = a.add_user(v, me)
                elif op == "user_update":
                    res = a.update_user(str(v.get("login", "")), {k: x for k, x in v.items() if k != "login"}, me)
                elif op == "user_delete":
                    a.delete_user(str(v.get("login", "")), me); res = {"ok": True}
                else:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                self._audit("admin." + op, str(v.get("login", "")), json.dumps({k: x for k, x in v.items() if k in ("role", "sites", "disabled")}, ensure_ascii=False))
                self._hdr_cache.clear()
                return self._json({"ok": True, "user": res} if isinstance(res, dict) and "login" in res else res)
            if u.path == "/api/hub/admin/mode":
                # 이 서버가 데이터를 밖으로 보내기 시작하거나, 밖에서 받기 시작하는 결정이다.
                # 관리자만 지나고(경로가 이미 관문), 누가 언제 바꿨는지 남긴다 — 토큰 값은 빼고.
                broken = self.api.hub_broken()
                if broken:
                    return self._json(
                        {"error": "이전 변경이 어긋난 채로 남아 있어 더 바꾸지 않습니다 — "
                                  + broken.splitlines()[0]},
                        HTTPStatus.CONFLICT)
                want = str(v.get("role") or "none")
                # 한 역할의 설정값이 **다른 역할로 흘러드는 길을 막는다**(GPT 5차).
                # 단독에 site_id 를 섞어 보내도 지금은 무시되지만, 무시하는 것과 거절하는 것은
                # 다르다 — 다음에 누가 이 값을 쓰기 시작하면 그 자리가 곧 우회로가 된다.
                ALLOWED = {"none": {"role"},
                           "central": {"role", "site_id", "site_name", "interval_sec", "send_reports"},
                           "site": {"role", "site_id", "site_name", "interval_sec", "send_reports", "send_feedback", "send_exec_reports",
                                    "hub_url", "hub_token"}}
                extra = sorted(set(v) - ALLOWED.get(want, set())) if isinstance(v, dict) else []
                if extra:
                    return self._json(
                        {"error": f"이 모드에서는 쓰지 않는 값이 있습니다: {', '.join(extra)} —"
                                  " 모드마다 받는 값이 다릅니다. 화면을 새로 고친 뒤 다시 해 주십시오"},
                        HTTPStatus.BAD_REQUEST)
                before = (self.api.hub_conf or {}).get("role", "none")
                before_conf = self.api.hub_conf
                if want == "none":
                    res = {"ok": True, "mode": self.api.switch_hub(None)}
                else:
                    c = {"role": want,
                         "site_id": str(v.get("site_id") or "").strip(),
                         "site_name": str(v.get("site_name") or "").strip(),
                         "interval_sec": v.get("interval_sec") or 60,
                         "send_reports": bool(v.get("send_reports", True))}
                    # 사이트 ID 는 쌓인 자료를 가리키는 이름이다. 한 번 못 박힌 뒤에 바꾸면
                    # **다른 사이트로 취급**되어 과거 자료와 끊긴다. 그래서 모드를 오가도 남는다.
                    #
                    # 이 검사는 전에 `want == "site"` 가지 안에 있었다. 그래서 포장본을 띄워
                    # 눌러 보니 **본사 모드로는 다른 ID 가 그대로 들어갔다** — 화면은 칸을
                    # 읽기 전용으로 잠가 두고 서버는 받는, 어긋난 상태였다. 그 뒤 사이트로
                    # 바꾸면 잠금이 걸려 옛 ID 를 요구하므로 화면과 설정이 서로 달라진다.
                    # 본사 서버도 자기 자료를 이 이름으로 묶어 두므로 똑같이 끊긴다.
                    # 그래서 **사이트 ID 를 받는 모든 모드**에 건다.
                    locked = hubmod.locked_site(self.api._base)
                    if locked and c["site_id"] != locked:
                        # 안내는 모드에 맞게 — 본사 서버에는 전화할 '본사 담당자' 가 없다
                        how = ("본사에 쌓인 자료가 이 이름으로 묶여 있습니다."
                               " 정말 바꿔야 한다면 본사 담당자와 함께 재등록하십시오"
                               if want == "site" else
                               "이 서버에 쌓인 자료가 이 이름으로 묶여 있습니다."
                               " 정말 바꿔야 한다면 이 서버의 수집 자료를 함께 옮겨야 하므로"
                               " 화면에서는 바꾸지 않습니다")
                        return self._json(
                            {"error": f"이 서버의 사이트 ID 는 '{locked}' 로 못 박혀 있습니다 —"
                                      " 바꾸면 다른 사이트로 취급되어 과거 자료와 끊깁니다. "
                                      + how},
                            HTTPStatus.BAD_REQUEST)
                    if want == "site":
                        # 로그인이 없으면 '관리자만' 이라는 경계가 없다. 그 상태에서 허용 목록마저
                        # 없으면 **접속만 되면 누구나 자료 반출을 켤 수 있다**(GPT 판정).
                        # 두 전제가 서로를 지우는 자리만 막는다 — 단독·본사는 그대로 된다.
                        no_login = not (self.api.auth_conf and self.api.auth_conf["mode"] != "off") \
                            and not self.password
                        if no_login and not hubmod.trusted(self.api._base):
                            return self._json(
                                {"error": "이 서버는 로그인이 없어 접속할 수 있는 사람이 모두 관리자입니다."
                                          " 그 상태에서는 보낼 수 있는 본사를 정해 두지 않으면"
                                          " 사이트 서버로 바꿀 수 없습니다 —"
                                          f" 서버의 conf/{hubmod.ALLOW_FILE} 에 허용할 본사 주소를"
                                          " 적어 두시거나, 로그인을 켜 주십시오"
                                          " (python3 -m logtriage.authmode --base <설치경로> local)"},
                                HTTPStatus.FORBIDDEN)
                        c["hub_url"] = str(v.get("hub_url") or "").strip()
                        # 인증서 검사 끄기·평문 허용은 없앴다 — 화면에서 보내 와도 받지 않는다
                        tok = str(v.get("hub_token") or "").strip()
                        # 비워서 보내면 쓰던 토큰을 그대로 둔다 — **다만 같은 곳일 때만.**
                        # 주소나 사이트가 바뀌었는데 물려주면 옛 토큰이 새 주소로 그대로
                        # 나간다(GPT 상 등급). 주기만 바꾸려는 경우를 위해 남긴 편의가
                        # 목적지 바꾸기와 겹치면 유출 경로가 된다.
                        if not tok:
                            if hubmod.same_target(self.api.hub_conf, c):
                                tok = self.api.hub_conf["hub_token"]
                            elif (self.api.hub_conf or {}).get("hub_token"):
                                return self._json(
                                    {"error": "보내는 곳이 바뀌었습니다 — 새 사이트 토큰을 넣어 주십시오."
                                              " 쓰던 토큰을 다른 주소로 보내지 않습니다"},
                                    HTTPStatus.BAD_REQUEST)
                        c["hub_token"] = tok
                    res = {"ok": True, "mode": self.api.switch_hub(c)}
                # **보내기는 아직 시작하지 않았다.** 근거를 먼저 남기고 그다음에 시작한다 —
                # 자료가 나갔는데 바꾼 기록이 없는 창을 두지 않는다(GPT 중상).
                what = f"{before} -> {want}" + (f" ({v.get('site_id')})" if want != "none" else "")
                try:
                    # 첫 기록은 '성공' 이 아니라 **바꾸기로 했다** 이다 — 시작이 뒤에 실패할 수 있다
                    a.audit(me, self._ip(), "hub.mode.prepare", what)
                except Exception:
                    self.api.rollback_hub(before_conf)
                    return self._json({"error": "바꾼 기록을 남기지 못해 되돌렸습니다 —"
                                                " 감사 기록이 되는지 확인한 뒤 다시 하십시오"},
                                      HTTPStatus.INTERNAL_SERVER_ERROR)
                try:
                    self.api.start_hub()
                except Exception as e:
                    a.audit(me, self._ip(), "hub.mode.failed", f"{what}: {e}", ok=False)
                    self.api.rollback_hub(before_conf)
                    return self._json({"error": f"바꾼 설정으로 시작하지 못해 되돌렸습니다: {e}"},
                                      HTTPStatus.INTERNAL_SERVER_ERROR)
                a.audit(me, self._ip(), "hub.mode.applied", what)
                return self._json(res)
            if u.path == "/api/hub/admin/recover":
                # **설정을 바꾸려고 서비스를 내리지 않는다**(사용자 지시). 서버가 스스로 하므로
                # 콘솔 명령처럼 두 프로세스가 같은 파일을 다투는 일이 없다.
                try:
                    res = self.api.clear_recovery()
                except ValueError as e:
                    return self._json({"error": str(e)}, HTTPStatus.CONFLICT)
                a.audit(me, self._ip(), "hub.recovery.cleared", str(res.get("was", "")))
                try:
                    self.api.start_hub()
                except Exception as e:                   # noqa: BLE001
                    return self._json({"error": f"풀었지만 보내기를 시작하지 못했습니다: {e}"},
                                      HTTPStatus.INTERNAL_SERVER_ERROR)
                return self._json(res)
            if u.path == "/api/hub/admin/identity_reset":
                if str(v.get("confirm")) != "1":
                    return self._json({"error": "되돌릴 수 없는 일입니다 — 확인이 필요합니다"},
                                      HTTPStatus.BAD_REQUEST)
                before_id = hubmod.locked_site(self.api._base)
                try:
                    res = self.api.reset_identity(v.get("site_id"), v.get("hub_token", ""))
                except ValueError as e:
                    return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
                a.audit(me, self._ip(), "hub.identity.reset",
                        f"{before_id} -> {res.get('now', '')}")
                try:
                    self.api.start_hub()
                except Exception:                        # noqa: BLE001
                    pass
                return self._json(res)
            if u.path.startswith("/api/hub/admin/"):
                if hub is None:
                    return self._json({"error": "본사(central) 서버에서만 사이트를 관리합니다"}, HTTPStatus.NOT_FOUND)
                sid = str(v.get("id", ""))
                if op == "site_add":
                    tok = hub.add_site(sid, str(v.get("name", "")))
                    res = {"ok": True, "token": tok, "hub_json": {"role": "site", "site_id": sid, "site_name": str(v.get("name", "") or sid),
                                                                  "hub_url": self._agent_base(), "hub_token": tok, "interval_sec": 60, "send_reports": True}}
                elif op == "site_reset":
                    res = {"ok": True, "token": hub.reset_token(sid)}
                elif op == "site_update":
                    hub.update_site(sid, v); res = {"ok": True}
                elif op == "site_delete":
                    hub.delete_site(sid); res = {"ok": True}
                else:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                self._audit("hub." + op, sid)
                return self._json(res)
            if u.path == "/api/hub/sync":   # 사이트 서버: 지금 본사로 보내기
                if not self.api.hub_client:
                    return self._json({"error": "본사 연동(conf/hub.json)이 설정되지 않았습니다"}, HTTPStatus.NOT_FOUND)
                self.api.hub_client.kick()
                return self._json({"ok": True})
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, TypeError, KeyError) as e:
            return self._json({"error": str(e)}, HTTPStatus.BAD_REQUEST)
        except Exception as e:
            sys.stderr.write(f"[admin] {type(e).__name__}: {e}\n")
            return self._json({"error": "처리 오류: 서버 로그 확인"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def _rulepack(self, length: int):
        ctype = self.headers.get("Content-Type", "")
        m = re.search(r"boundary=([^;]+)", ctype)
        if not m or length > 200 * 1024 * 1024:
            return self._json({"error": "multipart/form-data 필요"})
        body = self.rfile.read(length)
        boundary = ("--" + m.group(1).strip('"')).encode()
        parts = {}
        for seg in body.split(boundary)[1:]:
            if seg.strip() in (b"", b"--"):
                continue
            head, _, data = seg.partition(b"\r\n\r\n")
            nm = re.search(rb'name="([^"]+)"', head)
            if nm:
                parts[nm.group(1).decode()] = data.rstrip(b"\r\n")
        if "rpk" not in parts or "key" not in parts:
            return self._json({"error": "rpk 와 key 파일이 모두 필요합니다"})
        tmp = self.api._base / "uploads" / f"rulepack_{secrets.token_hex(4)}.rpk"
        tmp.write_bytes(parts["rpk"])
        try:
            return self._json(self.api.apply_rulepack_files(tmp, parts["key"], parts.get("confirm_fp", b"").decode("ascii", "ignore")[:64]))
        finally:
            tmp.unlink(missing_ok=True)


def load_tls(base: Path) -> dict | None:
    """conf/tls.json — 서버가 직접 HTTPS 로 받도록 한다(VPN·인터넷 구간용). 없으면 평문으로 받고 앞단(nginx)에 맡긴다.

    {"cert": "conf/server.crt", "key": "conf/server.key", "key_password": "", "client_ca": "", "min_version": "TLS1.2"}
      · client_ca 를 지정하면 그 기관이 발급한 클라이언트 인증서를 가진 접속만 받는다(상호 인증, VPN 대용).
    """
    f = Path(base) / "conf" / "tls.json"
    if not f.exists():
        return None
    conf = json.loads(f.read_text(encoding="utf-8-sig"))
    cert = Path(str(conf.get("cert", ""))).expanduser()
    key = Path(str(conf.get("key", ""))).expanduser()
    if not cert.is_absolute():
        cert = Path(base) / cert
    if not key.is_absolute():
        key = Path(base) / key
    if not cert.exists() or not key.exists():
        raise ValueError(f"conf/tls.json: 인증서·키 파일을 찾을 수 없습니다 ({cert}, {key})")
    conf["cert"], conf["key"] = str(cert), str(key)
    return conf


def tls_context(conf: dict) -> "ssl.SSLContext":
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = getattr(ssl.TLSVersion, str(conf.get("min_version", "TLS1.2")).replace(".", "_"), ssl.TLSVersion.TLSv1_2)
    ctx.load_cert_chain(conf["cert"], conf["key"], password=(conf.get("key_password") or None))
    ca = conf.get("client_ca")
    if ca:
        ctx.load_verify_locations(str(Path(ca)))
        ctx.verify_mode = ssl.CERT_REQUIRED      # 상호 인증(mTLS) — 회사 인증서가 있는 단말만
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS")
    return ctx


def setup_hint(api, host: str, port: int) -> str:
    """첫 기동 안내 — 계정이 없으면 관리자 계정을 만드는 주소와 1회용 초기 설정 코드를 알려 준다(2026-09-22)."""
    tok = getattr(api, "setup_token", "")
    if not tok:
        return ""
    where = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    fa = (getattr(api, "auth_conf", None) or {}).get("first_admin", "")
    who = f"           첫 관리자로 지정된 계정: {fa} (이 계정의 비밀번호만 정하면 됩니다)\n" if fa else ""
    # 아무 일도 하지 않는 설정이 파일에 적혀 있는 것이 가장 나쁘다 — 사람은 그 값을 믿는다.
    # setup_scope 는 더 이상 웹 경로를 열지 않으므로, 옛 값이 남아 있으면 그렇다고 말한다.
    scope = (getattr(api, "auth_conf", None) or {}).get("setup_scope", "token")
    old = ("\n           [알림] conf/auth.json 의 setup_scope=" + scope + " 는 **이제 쓰지 않습니다** -"
           "\n           웹으로 첫 계정을 만들 때는 설정과 무관하게 코드를 받습니다(앞단 프록시 뒤에서는"
           "\n           접속 주소로 '서버에 앉은 사람' 을 가려낼 수 없기 때문입니다)."
           if scope in ("loopback", "private") else "")
    return (f"[초기 설정] 아직 계정이 없습니다 - 아래 주소로 접속해 관리자 계정을 만드십시오.\n"
            + who +
            f"           http://{where}:{port}/setup?t={tok}\n"
            "           이 1회용 코드는 conf/setup-code.txt 에도 적었습니다. **이 코드를 아는 사람이\n"
            "           이 서버의 첫 관리자가 됩니다** - 아무에게나 알리지 마십시오.\n"
            "           (같은 PC 에서 열어도 코드가 필요합니다 - 앞단 프록시 뒤에서는 접속 주소로\n"
            "            '서버에 앉은 사람' 을 가려낼 수 없기 때문입니다.)\n"
            "           코드 없이 만들려면 서버 콘솔에서:  python3 -m logtriage.accounts"
            " --base <경로> add --email ○○@회사 --role admin" + old)


def make_server(host: str, port: int, base: Path, password: str | None, allow_dirs=(), db_url: str | None = None,
                api_cls=None, desktop: bool = False, native: bool | None = None, local_only: bool = False):
    """인스턴스별 Handler(세션·DB 분리) — serve()·테스트·데스크톱 내장 서버가 공용. 수집기 스레드는 호출자가 start/stop.
    native: ui.html 에 네이티브(pywebview) 파일 대화상자 사용을 알릴지. 기본은 desktop 과 같고, 브라우저로 여는 동반 실행기는 False."""
    left = prepare_base(base)   # 10차: 내장 지식 펼치기 → 8차 ④ 지식이 섞였을 수 있으면 자료를 열기 전에 멈춘다
    if left:
        raise SystemExit("[LogTriage] " + left)

    class BoundHandler(Handler):
        pass
    BoundHandler.api = (api_cls or ServerApi)(Path(base), [Path(d) for d in allow_dirs], db_url)
    if password and str(password).startswith(PW_KDF + "$") and _pw_parse(password) is None:   # 깨진 검증값을 평문으로 받지 않는다
        raise SystemExit("[LogTriage] 비밀번호 검증값의 형식·비용 값이 이 판에서 받는 범위가 아닙니다 — --hash-password 로 다시 만드십시오")
    _weak = weak_shared_password(password) if host not in ("127.0.0.1", "::1", "localhost") else ""
    if _weak:   # 21차: 누구나 아는 자리 값으로 LAN 에 열지 않는다
        raise SystemExit(f"[LogTriage] 공용 비밀번호가 {_weak}입니다 — LAN({host})에 열지 않습니다. server.conf / server.env 의 PASSWORD 를 바꾸십시오")
    BoundHandler.password = as_verifier(password)   # 8차 ⑪: 평문을 들고 있지 않는다 — 검증값만(참/거짓 판단은 그대로)
    if password and _pw_parse(password) is None and pw_ok(password, BoundHandler.password) is not True:
        raise SystemExit("[LogTriage] 공용 비밀번호 검증값을 만들었지만 확인되지 않습니다(KDF 오류) — 띄우지 않습니다")
    BoundHandler.desktop = desktop
    BoundHandler.native = desktop if native is None else bool(native)
    BoundHandler.boot_token = secrets.token_hex(16) if desktop else None   # 데스크톱 창이 세션을 얻는 1회성 비밀(프로세스 안에서만)
    # 이 PC 전용(로그인 없음)은 창 모드 + 루프백 수신 + 서버 비밀번호 없음일 때만 — 조건이 하나라도 어긋나면 켜지 않는다
    BoundHandler.local_only = bool(local_only and desktop and not password and host in ("127.0.0.1", "::1", "localhost"))
    BoundHandler._sessions = set()
    BoundHandler._fail = {}        # 서버 인스턴스별(테스트·데스크톱 내장 서버가 서로 섞이지 않게)
    BoundHandler._hdr_cache = {}
    httpd = ThreadingHTTPServer((host, port), BoundHandler)
    httpd.daemon_threads = True
    httpd.tls = False
    tls = load_tls(Path(base))
    if tls:                                   # 서버가 직접 HTTPS 로 받는다(앞단 없이 VPN·인터넷 구간에 바로 노출 가능)
        httpd.socket = tls_context(tls).wrap_socket(httpd.socket, server_side=True)
        httpd.tls = True
    return httpd, BoundHandler


NL = chr(10)

LOOPBACK = ("127.0.0.1", "::1", "localhost")


def auth_banner(conf: dict | None, password: str | None) -> str:
    """기동 줄에 적는 로그인 상태 — **사실만 적는다.**

    전에는 portal 과 단일 비밀번호만 알아서, 회사 이메일 계정 로그인(local)인 서버에
    `auth=off` 라고 적었다. 그 줄은 담당자가 '로그인이 걸렸는지' 확인하는 유일한 자리다.
    거짓을 적으면 멀쩡한 서버를 비밀번호 걸려고 다시 띄우거나, 열린 줄 알고 그냥 둔다.
    """
    mode = (conf or {}).get("mode")
    if mode == "local":
        return "local(계정)" + ("+password" if password else "")
    if mode == "portal":
        return "portal:" + ((conf or {}).get("portal") or {}).get("method", "?")
    if password:
        return "password"
    return "off(로그인 없음)"


def guard_open_server(host: str, conf: dict | None, password: str | None) -> str:
    """로그인 없이 **망에 열려는** 기동을 막는다 — 막을 이유를 돌려준다(없으면 빈 글자).

    로그인이 없으면 접속할 수 있는 사람이 모두 관리자다. 자산 기준을 바꾸고, 본사 연동을 켜고,
    사용자를 만들 수 있다. 그 상태를 망에 열어 두는 것은 배너로 덮을 수 있는 일이 아니다.

    이 PC 안에서만 여는 것(127.0.0.1·::1)은 그대로 둔다 — 시험과 개인 사용을 막을 이유가 없다.
    """
    if password:
        return ""                                  # 단일 비밀번호가 걸려 있다
    if conf and conf.get("mode") in ("local", "portal"):
        return ""                                  # 계정 로그인을 쓴다
    if str(host).strip() in LOOPBACK:
        return ""                                  # 이 PC 안에서만 열린다
    return ("이 서버는 **로그인이 없는데 망에 열려 있습니다**(--host " + str(host) + ")." + NL
            + "접속할 수 있는 사람이 모두 관리자가 됩니다 — 자산 기준을 바꾸고, 본사로 자료를 보내도록" + NL
            + "설정하고, 사용자를 만들 수 있습니다. 그대로 띄우지 않습니다." + NL + NL
            + "다음 중 하나로 다시 띄워 주십시오." + NL
            + "  1) 계정 로그인을 켭니다(권장)  : python3 -m logtriage.authmode --base <설치경로> local" + NL
            + "     그 뒤 첫 접속에서 [관리자 계정 만들기] 가 뜹니다." + NL
            + "  2) 단일 비밀번호를 겁니다      : --password-stdin  (한 줄을 파이프로 넣습니다)" + NL
            + "     무인 기동은 --password-file <0600 파일>." + NL
            + "     **--password 로 적지 마십시오** — 프로세스 목록(/proc/<PID>/cmdline)에 보입니다." + NL
            + "  3) 이 PC 안에서만 씁니다        : --host 127.0.0.1")


def _is_standalone(base) -> bool:
    """이 폴더의 판정 지식이 exe 내장본을 펼친 것인가(세대 기록 출처) — 단독 실행(10차)."""
    try:
        g = json.loads((Path(base) / "knowledge-gen.json").read_text(encoding="utf-8"))
        return str(g.get("source", "")).startswith("내장 지식")
    except (OSError, ValueError, AttributeError):
        return False


def prepare_base(base) -> str:
    """기동 준비(10차) — exe 옆에 판정 지식이 하나도 없으면 exe 안 내장 지식을 펼친 뒤(knowledge_seed), 기동 거부 사유를 돌려준다.
    창·서버(--serve)·내장 서버가 모두 이 한 함수로 — 단독 실행용 exe 하나만 옮겨도 분석이 된다."""
    import logging as _lg
    from .knowledge_seed import refresh_user_home, seed
    try:
        moved = refresh_user_home(Path(base))   # 14차: 사용자 자리에서 exe 판이 오르면 옛 내장 지식을 백업으로 옮기고 새로 펼친다
    except OSError as e:
        return f"사용자 자료 자리의 옛 지식을 백업으로 옮기지 못했습니다({type(e).__name__}: {e}) — 위치: {base}"
    if moved:
        _lg.getLogger(__name__).info("user home knowledge refreshed (old → %s)", moved)
    r = seed(Path(base))
    if r.get("seeded"):
        _lg.getLogger(__name__).info("knowledge seeded from exe: %s", ",".join(r["seeded"]))
    if r.get("error"):
        return r["error"]
    return release_leftover(base)


def release_leftover(base) -> str:
    """8차 ④ · GPT 65차: 지식 출시(knowledge_release)가 전환 도중 멈춘 흔적(.lt-know-old·.lt-know-new)이 있으면 지식이 섞였을 수 있다 —
    앱은 기동을 거부한다(혼합 지식으로 판정하지 않게). 개발 PC 에서 knowledge_release 를 다시 돌리면 시작할 때 구판으로 되돌린다."""
    b = Path(base)
    left = [n for n in (".lt-know-old", ".lt-know-new") if (b / n).exists()]
    if not left:
        if (b / ".lt-install-pending").exists():   # 9차 ⑥ · GPT 71차: 이동 설치가 중간에 멈춤 — 실행 파일이 섞였을 수 있다
            return ("이동 설치가 중간에 멈춘 흔적(.lt-install-pending)이 있습니다 — 실행 파일이 섞였을 수 있어 띄우지 않습니다.\n"
                    "개발 PC 에서: python tools/build/install_move.py <빌드 폴더> … 를 다시 실행하면 먼저 지난 설치를 되돌립니다")
        # GPT 70·71차 P0: 흔적 없이 섞인 경우(한 폴더만 바뀜) — 배포 폴더 루트의 세대 기록과 세 폴더 내용 지문 대조
        from .knowledge_gen import check_gen
        return check_gen(b)
    return ("지식 출시가 전환 도중 멈춘 흔적이 있습니다(" + ", ".join(left) + ") — 판정 지식이 섞였을 수 있어 띄우지 않습니다.\n"
            "개발 PC 에서: python tools/build/knowledge_release.py --note \"복구\" (시작할 때 구판으로 되돌림)")


def _pick_version(hv: dict, host: str, product: str, instance: str) -> tuple:
    """8차 아이디어 8: (호스트, 제품[, 인스턴스]) 의 판 기록 고르기 → (기록 | None, 혼재 목록).
    파일에 인스턴스가 있으면 그 인스턴스 기록 → 없으면 호스트 전체('') 기록. 파일에 인스턴스가 없는데 그 호스트·제품에
    판이 다른 기록이 둘 이상이면 고르지 않는다(판 혼재 가능 — 어느 인스턴스 로그인지 모름)."""
    p0 = product.split("-")[0]
    cand = {k[2]: r for k, r in hv.items() if k[0] == host and k[1].split("-")[0] == p0}
    if instance:   # GPT 64차 P1: 인스턴스를 아는데 그 기록이 없으면 호스트 전체 판을 물려받지 않는다(다른 인스턴스 판일 수 있음) — 추정 유지
        return cand.get(instance), []
    vers = sorted({r["version"] for r in cand.values()})
    if len(vers) > 1:
        return None, sorted(f"{k or '호스트 전체'}={r['version']}" for k, r in cand.items())
    if not cand:
        return None, []
    return max(cand.values(), key=lambda r: r["at"]), []


PW_SOURCE: list = []      # 비밀번호를 어느 길로 받았나 — 값이 아니라 **길만** 남긴다

# ── 8차 아이디어 11: 공용 비밀번호(--password·파일·표준 입력·환경변수)를 느린 KDF 검증값으로만 들고 있는다 ──
# 기동 때 한 번 scrypt(N=2^15, r=8, p=1, 소금 16바이트) 검증값으로 바꾸고 평문은 버린다. 비교는 매번 같은 KDF 로(상수 시간 비교).
# 비밀번호 파일에는 평문 대신 검증값(lt-scrypt$…)을 둘 수 있다 — --hash-password(표준 입력 → 검증값 출력)·--hash-password-file(제자리 변환).
# 한계: 프로세스가 평문을 받는 순간(표준 입력·파일 읽기)은 있다. 검증값 파일이 새면 오프라인 대입은 여전히 된다(느려질 뿐).
PW_KDF = "lt-scrypt"
# 21차(10-26): 예시 파일의 자리 값을 그대로 둔 채 LAN 에 여는 것을 막는다(server.conf.example · server.env.example 의 값은 누구나 안다)
PW_PLACEHOLDERS = frozenset(("바꾸" "세요", "change-me", "changeme", "password"))   # 예시 파일 값 — 말투 시험(합쇼체)이 안내문으로 읽지 않게 나눠 적음


# 22차(GPT 153 P1-01): 자리 값만 막으면 12345678 · admin2026 같은 값으로 LAN 에 열린다 — 추측 가능한 꼴도 공통으로 거부
PW_COMMON_WORDS = frozenset(("admin", "administrator", "root", "logtriage", "solideo", "solideos", "test", "guest", "user", "welcome",
                             "qwerty", "qwer", "asdf", "letmein", "pass", "passwd", "password", "manager", "server", "monitor", "agent", "secret"))
_PW_LEET = str.maketrans({"@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t"})
_PW_RUNS = ("abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiopasdfghjklzxcvbnm", "1qaz2wsx3edc4rfv5tgb")


def _pw_guessable(pw: str) -> str:
    p = pw.strip().lower()
    if len(p) < 8:
        return "8자 미만"
    if len(set(p)) <= 2:
        return "같은 글자 반복"
    core = re.sub(r"^[\d\W_]+|[\d\W_]+$", "", p)          # 앞뒤 숫자·기호를 떼면(admin2026 → admin)
    if not core:
        return "숫자 · 기호만"
    leet = re.sub(r"^[\d\W_]+|[\d\W_]+$", "", re.sub(r"[\d\W_]+$", "", p).translate(_PW_LEET))   # P@ssw0rd!! → password
    if core in PW_COMMON_WORDS or leet in PW_COMMON_WORDS:
        return "흔한 낱말에 숫자 · 기호만 붙인 값"
    if any(p in r or p in r[::-1] for r in _PW_RUNS):
        return "키보드 · 연속 글자"
    return ""


def weak_shared_password(password, strict: bool = False) -> str:
    """공용(서버) 비밀번호가 약한 까닭 — 괜찮으면 빈 문자열. 검증값(lt-scrypt$…)은 원문을 모르므로 판단하지 않는다.
    공통(리눅스 포함): 예시 파일의 자리 값 · 추측 가능한 꼴(8자 미만 · 같은 글자 반복 · 숫자만 · 흔한 낱말+숫자 · 키보드 연속)을 거부.
    strict: 윈도우 exe 의 server.conf 처럼 사람이 손으로 적는 값 — 10자 미만도 거부(리눅스 설치는 무작위 12자를 만든다)."""
    pw = str(password or "")
    if not pw or pw.startswith(PW_KDF + "$"):
        return ""
    if pw.strip().lower() in PW_PLACEHOLDERS:
        return "예시 파일의 값 그대로"
    g = _pw_guessable(pw)
    if g:
        return "추측하기 쉬운 값(" + g + ")"
    if strict and len(pw) < 10:
        return "10자 미만"
    return ""
# GPT 64차: OWASP 권장 최소 scrypt N=2^17·r=8·p=1(메모리 약 128MiB, 이 PC 실측 0.38초). 메모리 고갈 남용을 막게 동시 계산은 2개까지.
_PW_N_LOG2, _PW_R, _PW_P = 17, 8, 1
_PW_MAXMEM = 256 << 20          # maxmem 을 명시한다(파이썬·OpenSSL 기본값이 작아 'memory limit exceeded' 가 나는 조합이 있다)
_PW_SLOTS = threading.BoundedSemaphore(2)


def _scrypt(pw: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    with _PW_SLOTS:
        return hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=1 << n, r=r, p=p, maxmem=_PW_MAXMEM, dklen=dklen)


def pw_verifier(pw: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = _scrypt(pw, salt, _PW_N_LOG2, _PW_R, _PW_P, 32)
    return f"{PW_KDF}${_PW_N_LOG2}${_PW_R}${_PW_P}${salt.hex()}${dk.hex()}"


def _pw_parse(v: str):
    try:
        kind, n, r, p, salt, dk = str(v or "").split("$")
        if kind != PW_KDF or not (14 <= int(n) <= 18) or int(r) != 8 or not (1 <= int(p) <= 2) or len(salt) != 32 or len(dk) != 64:
            return None
        return int(n), int(r), int(p), bytes.fromhex(salt), bytes.fromhex(dk)
    except (ValueError, TypeError):
        return None


def as_verifier(pw: str | None) -> str | None:
    """평문이면 검증값으로, 이미 검증값이면 그대로."""
    if not pw:
        return None
    return pw if _pw_parse(pw) else pw_verifier(pw)


def pw_ok(given: str, verifier: str | None):
    """True = 맞음 · False = 틀림 · None = 서버가 확인하지 못함(KDF 메모리·내부 오류) — GPT 64차: 확인 못 함을 '틀림'으로 세면
    정상 사용자가 잠기거나 속도 제한에 걸린다. 부르는 쪽은 None 이면 거절하되 실패로 세지 않는다(인증 우회는 없음 — 통과는 True 뿐)."""
    parts = _pw_parse(verifier or "")
    if not parts or not given or len(str(given)) > 1024:
        return False
    n, r, p, salt, dk = parts
    try:
        got = _scrypt(str(given), salt, n, r, p, len(dk))
    except (ValueError, MemoryError, OverflowError):
        return None
    return hmac.compare_digest(got, dk)


def hash_password_file(path: Path) -> int:
    """비밀번호 파일의 평문을 검증값으로 제자리 바꾼다(권한 유지·바꿔치기 쓰기·디스크에 쓴 뒤 교체). 이미 검증값이면 그대로 둔다.
    링크(심볼릭·정션)거나 일반 파일이 아니면 거절 — 링크를 따라가 다른 파일을 덮지 않는다(GPT 64차)."""
    import stat as _stat
    try:
        st = os.lstat(path)
    except OSError as e:
        authmod._say(f"[LogTriage] {path} 를 읽지 못했습니다: {e}")
        return 2
    junction = bool(getattr(os.path, "isjunction", lambda _p: False)(path))
    if _stat.S_ISLNK(st.st_mode) or not _stat.S_ISREG(st.st_mode) or junction:
        authmod._say(f"[LogTriage] {path} 는 링크이거나 일반 파일이 아닙니다 — 바꾸지 않습니다")
        return 2
    t = path.read_text(encoding="utf-8").strip()
    if not t:
        authmod._say(f"[LogTriage] {path} 가 비어 있습니다")
        return 2
    if _pw_parse(t):
        authmod._say(f"[LogTriage] {path} 는 이미 검증값입니다 — 바꾸지 않았습니다")
        return 0
    v = pw_verifier(t)
    if pw_ok(t, v) is not True:   # 만든 검증값으로 실제 확인이 되는지 먼저 — 안 되면 원본을 건드리지 않는다
        authmod._say("[LogTriage] 검증값을 만들었지만 확인되지 않습니다 — 원본을 그대로 둡니다")
        return 1
    tmp = path.with_name(path.name + ".lt-new")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(v + NL)
        f.flush()
        os.fsync(f.fileno())          # 정전에도 반쪽 파일로 바뀌지 않게 — 교체 전에 디스크에
    if os.name == "nt":
        # GPT 65차: os.replace 는 새 파일의 보안 설명자(폴더 상속)를 남긴다 — 원본의 NTFS 접근 권한(DACL)이 사라진다.
        # ReplaceFileW 는 바뀌는 파일의 ACL·속성을 그대로 둔 채 내용만 바꾼다(같은 볼륨, 원자적).
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.ReplaceFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
        if not k32.ReplaceFileW(str(path), str(tmp), None, 0, None, None):
            err = ctypes.get_last_error()
            try:
                tmp.unlink()
            except OSError:
                pass
            authmod._say(f"[LogTriage] 바꾸지 못했습니다(Windows 오류 {err}) — 원본은 그대로입니다")
            return 1
    else:
        try:
            os.chmod(tmp, st.st_mode & 0o777)
            os.chown(tmp, st.st_uid, st.st_gid)
        except (OSError, AttributeError):
            pass
        os.replace(tmp, path)
    authmod._say(f"[LogTriage] {path} 의 비밀번호를 검증값({PW_KDF})으로 바꿨습니다 — 이 파일로는 더 이상 다른 곳에 로그인할 수 없습니다(평문이 없음)")
    return 0


def read_password(a) -> str | None:
    """비밀번호를 받는 길 — **명령행 인자는 마지막 수단이다.**

    리눅스에서 /proc/<PID>/cmdline 은 누구나 읽는다. 표준 입력으로 받으면 디스크에도
    인자에도 남지 않고, 파일로 받으면 권한으로 막을 수 있다.
    """
    if getattr(a, "password_stdin", False):
        line = sys.stdin.readline()
        PW_SOURCE.append("stdin")
        return line.strip() or None
    if getattr(a, "password_file", ""):
        p = Path(a.password_file)
        try:
            mode = p.stat().st_mode
        except OSError as e:
            raise SystemExit(f"[LogTriage] 비밀번호 파일을 읽지 못했습니다: {e}")
        if os.name == "posix" and (mode & 0o077):
            raise SystemExit("[LogTriage] 비밀번호 파일을 다른 사용자가 읽을 수 있습니다 — "
                             f"chmod 600 {p} 로 바꾼 뒤 다시 띄우십시오")
        PW_SOURCE.append("file")
        t = p.read_text(encoding="utf-8").strip() or None
        if t and not _pw_parse(t):   # 8차 ⑪: 파일에 평문이 있으면 알린다(자동으로 바꾸지 않는다 — 같은 파일을 다른 도구가 쓸 수 있다)
            authmod._say("[LogTriage] 알림: 비밀번호 파일에 평문이 있습니다 — 검증값으로 바꾸려면"
                         + NL + f"             python -m logtriage.server --hash-password-file {p}")
        return t
    env = os.environ.get("LOGTRIAGE_PASSWORD", "")
    if env:
        PW_SOURCE.append("env")
        return env
    if getattr(a, "password", ""):
        PW_SOURCE.append("cmdline")        # 기동 기록에 남긴다 — 값은 적지 않는다
        authmod._say("[LogTriage] 주의: --password 로 준 비밀번호는 **프로세스 목록에 그대로 보입니다**"
                     + NL + "           (/proc/<PID>/cmdline · ps -ef · 셸 기록). 운영에서는 다음을 쓰십시오:"
                     + NL + "             · 계정 로그인:  python3 -m logtriage.authmode --base <경로> local"
                     + NL + "             · 표준 입력:    ... --password-stdin   (한 줄을 파이프로)"
                     + NL + "             · 파일:         ... --password-file <0600 파일>")
        return a.password
    return None


def server_password_stop(password) -> str:
    """22차(GPT 165 P1-01): 서버형은 앞단(nginx)이 LAN 을 받아 앱은 127.0.0.1 에 뜬다 — 수신 주소로는 노출을 알 수 없다.
    그래서 서버형 기동(serve · --check-start)은 주소와 관계없이 약한 공용 비밀번호를 거부한다(이 PC 혼자 쓰면 비밀번호를 비우면 된다)."""
    w = weak_shared_password(password)
    if not w:
        return ""
    return ("공용 비밀번호가 " + w + "입니다 — 서버형은 앞단(nginx)을 거쳐 LAN 에 열리므로 그대로 띄우지 않습니다." + NL
            + "  정식 설치: /etc/logtriage/server.env 의 LOGTRIAGE_PASSWORD 를 바꾼 뒤 systemctl restart logtriage-server" + NL
            + "  구동 테스트(run.sh): 비밀번호 파일(LOGTRIAGE_PASSWORD_FILE)의 값을 바꾼 뒤 다시 실행" + NL
            + "  규칙: 예시 값 · 8자 미만 · 숫자만 · 같은 글자 반복 · 흔한 낱말+숫자(admin2026 · P@ssw0rd) · 키보드 연속(qwerty)은 받지 않습니다." + NL
            + "  미리 확인: 새 비밀번호를 한 줄로 넣어  python3 -m logtriage.server --check-password --password-stdin")


def no_login_stop(host: str, conf: dict | None, password, local_only: bool) -> str:
    """22차(GPT 167 조건부 P0): 프록시 머리글은 출처 추정일 뿐 인증 경계가 아니다 — 서버형에서 '로그인 없음'은
    기동하는 사람이 '이 PC 전용'을 밝혔을 때(--local-only, run.sh 가 루프백 바인드에만 붙임)만 허용한다.
    systemd(앞단 nginx, 앱 127.0.0.1)는 붙이지 않으므로 계정 로그인 또는 공용 비밀번호 없이는 뜨지 않는다."""
    if password or local_only:
        return ""
    if conf and conf.get("mode") in ("local", "portal"):
        return ""
    return ("이 서버는 **로그인 없이** 띄우려 합니다(--host " + str(host) + "). 서버형은 앞단(nginx)을 거쳐 망에 열릴 수 있어" + NL
            + "'이 PC 안에서만'이라고 밝힌 기동만 로그인 없이 띄웁니다." + NL
            + "  1) 계정 로그인을 켭니다(권장)  : python3 -m logtriage.authmode --base <설치경로> local" + NL
            + "  2) 단일 비밀번호를 겁니다      : --password-stdin 또는 --password-file <0600 파일>" + NL
            + "  3) 정말 이 PC 안에서만 씁니다  : bash run.sh <포트> local   (직접 띄우면 --host 127.0.0.1 --local-only)")


def start_decision(host: str, base: Path, password: str | None, local_only: bool = False) -> dict:
    """이 조합으로 띄울 수 있는가 — **서버가 판정한다.**

    기동 스크립트가 같은 규칙을 다시 구현하면 두 곳이 갈라진다(이 제품에서 이미 여러 번
    겪었다). 그래서 스크립트는 이 판정을 불러 쓴다: `--check-start`.
    설정 파일이 아직 없으면 **첫 기동 기본값**으로 판단한다 — serve() 가 곧 그 값으로 만든다.
    """
    conf = authmod.load_conf(base)
    if conf is None:
        conf = {"mode": authmod.FIRST_RUN_CONF.get("mode", "off")}
    stop = (guard_open_server(host, conf, password) or server_password_stop(password)
            or no_login_stop(host, conf, password, local_only and str(host).strip() in LOOPBACK))
    # 한 자료 폴더에는 서버 하나다(SQLite·예약 작업·감사 기록을 함께 쓴다). 이것을 여기서
    # 보지 않으면, 포트만 바꿔 띄운 두 번째 서버가 **포트를 잡은 뒤** 자동화 자물쇠에서
    # 죽는다 — 운영자는 역추적만 본다(현장 기동 기록, 2026-10-02).
    if not stop:
        pid = runlock.running(base)
        if pid:
            who = f"(프로세스 번호 {pid})" if pid > 0 else "(번호를 읽지 못했습니다)"
            stop = (f"이 자료 폴더를 이미 다른 LogTriage 서버가 쓰고 있습니다 {who}." + NL
                    + f"           폴더: {base}" + NL
                    + "           한 자료 폴더에는 서버 하나만 띄울 수 있습니다 —"
                    + " 분석 이력·예약 작업·감사 기록을 함께 쓰기 때문입니다." + NL
                    + "           떠 있는 것을 먼저 멈추십시오:  bash stop.sh" + NL
                    + "           확인:  ps -eo pid,user,args | grep '[l]ogtriage.server'" + NL
                    + "           다른 서버를 함께 띄우려면 자료 폴더를 따로 주십시오(--base).")
    return {"allowed": not stop, "reason": stop, "mode": conf.get("mode", ""),
            "bind": host, "has_password": bool(password)}


def serve(host: str, port: int, base: Path, password: str | None, allow_dirs: list[Path], db_url: str | None = None,
          local_only: bool = False):
    conf0 = authmod.ensure_conf(base)   # 설정이 없으면 만들어 준다(2026-10-01 기본값: 계정 로그인)
    stop = (guard_open_server(host, conf0, password) or server_password_stop(password)
            or no_login_stop(host, conf0, password, local_only and str(host).strip() in LOOPBACK))
    if stop:
        # 콘솔 부호(cp949 등)로 못 쓰는 글자가 있어도 **막는 이유는 반드시 보여야 한다** —
        # 그냥 print 하면 역추적만 남고 왜 안 떴는지 알 수 없다(실제로 그렇게 됐다)
        authmod._say(NL + "[LogTriage] 기동하지 않았습니다" + NL + stop)
        raise SystemExit(2)
    if os.environ.get("LOGTRIAGE_PROXY_SECRET", "").strip() and not proxy_secret():
        authmod._say("[LogTriage] 주의: LOGTRIAGE_PROXY_SECRET 이 32자보다 짧아 쓰지 않습니다 — nginx 뒤 접속자 주소를 믿지 않으므로"
                     + NL + "           평문(HTTP) 접속은 거절되고 로그인 시도 제한은 nginx 주소 하나로 묶입니다. install.sh 를 다시 실행하면 새로 만듭니다.")
    # **자물쇠를 포트보다 먼저 쥔다.** 전에는 포트를 잡고 화면 안내까지 찍은 뒤 자동화
    # 자물쇠에서 죽었다 — 운영자에게는 '떴다가 역추적' 으로 보였다. 못 쥐면 아무것도
    # 건드리지 않고 왜 못 뜨는지만 말한다(현장 기동 기록, 2026-10-02).
    _held = runlock.acquire(base)
    if _held is None:
        pid = runlock.running(base)
        who = f" (프로세스 번호 {pid})" if pid > 0 else ""
        authmod._say(NL + "[LogTriage] 기동하지 않았습니다" + NL
                     + f"           이 자료 폴더를 이미 다른 LogTriage 서버가 쓰고 있습니다{who}." + NL
                     + f"           폴더: {base}" + NL
                     + "           한 자료 폴더에는 서버 하나만 띄울 수 있습니다 —"
                     + " 분석 이력·예약 작업·감사 기록을 함께 쓰기 때문입니다." + NL
                     + "           떠 있는 것을 먼저 멈추십시오:  bash stop.sh" + NL
                     + "           확인:  ps -eo pid,user,args | grep '[l]ogtriage.server'" + NL
                     + "           다른 서버를 함께 띄우려면 자료 폴더를 따로 주십시오(--base).")
        raise SystemExit(2)
    httpd, handler = make_server(host, port, base, password, allow_dirs, db_url)
    api = handler.api
    hint = setup_hint(api, host, port)
    if hint:
        print(hint, flush=True)
    if api.auth_conf and api.auth_conf.get("require_https", "auto") != True and not getattr(httpd, "tls", False):
        print("[알림] 평문(HTTP) 접속을 당분간 허용합니다 - 추후 패치에서 차단될 예정입니다." + chr(10)
              + "       그 전에 conf/tls.json 에 인증서를 달거나(서버 직접 HTTPS) 앞단에 TLS 를 두고"
              + " conf/auth.json 의 require_https 를 true 로 올리십시오.", flush=True)
    # 비밀번호를 **어느 길로** 받았는지 남긴다(값은 남기지 않는다). 경고만 하면 아무도 세지
    # 않는다 — 기록이 있어야 '아직 명령행으로 돌고 있는 서버' 를 찾을 수 있다(GPT 20차).
    try:
        api.auth.audit("(기동)", "", "server.start",
                       f"auth={auth_banner(api.auth_conf, password)}",
                       ("비밀번호 경로: " + ",".join(PW_SOURCE)) if PW_SOURCE else "")
    except Exception:
        pass
    from .crypto import backend as _cbk
    if _cbk() != "cryptography":
        print("[알림] 검증된 암호 라이브러리(cryptography)가 없어 자체 구현으로 동작합니다 - "
              "운영 전에 pip install cryptography 를 권합니다(보안 검토·납품 심사 대비).", flush=True)
    print(f"[LogTriage server] {'https' if getattr(httpd, 'tls', False) else 'http'}://{host}:{port}  base={base}  db={api.store.describe()}  "
          f"auth={auth_banner(api.auth_conf, password)}  hub={(api.hub_conf or {}).get('role', 'none')}  allow={[str(d) for d in allow_dirs]}  nms=/nms resources=/resources", flush=True)
    # 판 지문을 **여기서 한 번** 구해 메모리에 못 박는다. 뒤로는 디스크를 다시 읽지 않는다 —
    # 옛 프로세스가 떠 있는데 새 파일만 덮어쓴 상황을 잡으려는 값이기 때문이다(GPT 8차).
    authmod._say(f"[LogTriage] 제품 판 {BUILD} · 판 지문 {buildid.current()}")
    # 돌고 있는 동안 자물쇠를 쥔다. 관리 명령(hubadmin)은 **다른 프로세스**라 서버 안의
    # 자물쇠가 닿지 않는다 — 그 명령이 도는 서버와 동시에 파일을 고치면 돌고 있는 것과
    # 디스크가 어긋난다(GPT 8차). 프로세스가 죽으면 OS 가 자물쇠를 풀어 준다.
    # (자물쇠는 위에서 포트보다 먼저 쥐었다. 여기서는 쥔 채로 두기만 한다.)
    api.automation.start()
    broken = api.hub_broken()
    if broken:
        # 지난번에 모드를 바꾸다 어긋난 채로 남았다 — 표식만 남기고 다시 보내면 뜻이 없다.
        # 사람이 확인해 표식을 지울 때까지 본사 전송을 시작하지 않는다(GPT 권고).
        # 표식이 생겼다는 것은 새 설정·옛 설정·실행 중인 전송기·감사 기록 사이의 아귀를
        # 맞추지 못했다는 뜻이다. **표식만 지운다고 설정이 맞다는 보장이 없다**(GPT 중상).
        # 그래서 무엇을 확인한 뒤 지우라고 적는다.
        # **표식을 손으로 지우라고 하지 않는다**(GPT 7차). 그것이 정식 절차가 되면,
        # 같은 손놀림으로 실제 송신했던 서버의 잠금도 풀 수 있다고 가르치는 셈이다.
        # 검사를 지나야 풀리는 명령을 안내한다.
        authmod._say("[LogTriage] 본사 전송을 시작하지 않습니다 — " + broken.splitlines()[0] + chr(10)
                     + "           이 서버의 로그 분석·자산·게시판은 그대로 쓸 수 있습니다." + chr(10)
                     + "           [통합 현황] 화면에서 검사하고 다시 켤 수 있습니다 —"
                     + " **서비스를 다시 시작하지 않아도 됩니다.**" + chr(10)
                     + "           화면을 열 수 없을 때만 콘솔에서:"
                     + "  python3 -m logtriage.hubadmin --base " + str(base) + " status")
    elif api.hub_client:
        api.hub_client.start()
    old_term = None
    if threading.current_thread() is threading.main_thread():
        import signal
        old_term = signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=httpd.shutdown, daemon=True).start())
    try:
        api.collector.start()  # 인프라 감시 수집기
        api.warm_up()  # 룰·코드 캐시·대시보드 요약 예열
        from .gui.app import _diag_log   # 10차 ⑦: 서버형도 기동 자기진단 한 줄
        threading.Thread(target=_diag_log, args=(api,), name="lt-diag", daemon=True).start()
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        api.automation.stop()
        if api.hub_client:
            api.hub_client.stop()
        api.collector.stop()
        httpd.server_close()
        if old_term is not None:
            signal.signal(signal.SIGTERM, old_term)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LogTriage 서버형(Linux) — 브라우저 접속 웹 UI")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.environ.get("LOGTRIAGE_PORT", "8088")))
    ap.add_argument("--base", default=os.environ.get("LOGTRIAGE_BASE", ""), help="룰·코드·분석 이력·업로드가 놓이는 설치 경로")
    ap.add_argument("--password", default="", help="(권장하지 않음) 접속 비밀번호 — **프로세스 목록에 보입니다**")
    ap.add_argument("--password-file", default=os.environ.get("LOGTRIAGE_PASSWORD_FILE", ""),
                    help="접속 비밀번호를 담은 파일(0600). 명령행에 비밀번호를 적지 않는 길")
    ap.add_argument("--password-stdin", action="store_true",
                    help="접속 비밀번호를 표준 입력에서 한 줄 읽습니다(권장)")
    ap.add_argument("--check-start", action="store_true",
                    help="띄우지 않고 **띄울 수 있는지만** 봅니다 — 기동 스크립트가 씁니다(0=가능, 2=막힘)")
    ap.add_argument("--local-only", action="store_true",
                    help="이 PC 안에서만 쓴다고 밝힙니다(루프백 바인드일 때만 뜻이 있음) — 로그인 없는 서버형은 이것이 있어야 뜹니다(run.sh local)")
    ap.add_argument("--check-password", action="store_true",
                    help="띄우지 않고 공용 비밀번호가 이 판의 규칙을 통과하는지만 봅니다(0=통과, 2=약함) — 패치 전 진단이 씁니다")
    ap.add_argument("--hash-password", action="store_true",
                    help="표준 입력의 비밀번호 한 줄을 검증값(lt-scrypt$…)으로 바꿔 출력하고 끝냅니다 — 비밀번호 파일에 평문 대신 넣는 값")
    ap.add_argument("--hash-password-file", default="",
                    help="비밀번호 파일의 평문을 검증값으로 제자리 바꾸고 끝냅니다(권한 유지)")
    ap.add_argument("--allow-dir", action="append", default=[], help="서버 로컬에서 직접 분석할 수 있는 로그 디렉터리(반복 지정)")
    ap.add_argument("--db", default=os.environ.get("LOGTRIAGE_DB", ""),
                    help="저장소 URL — sqlite:////경로/logtriage.db (기본 <base>/data/logtriage.db) 또는 postgresql://user:pw@host:5432/db")
    a = ap.parse_args(argv)
    if a.hash_password:          # 8차 ⑪
        line = sys.stdin.readline().strip()
        if not line:
            authmod._say("[LogTriage] 표준 입력에 비밀번호 한 줄을 넣으십시오")
            return 2
        sys.stdout.write(pw_verifier(line) + NL)
        return 0
    if a.hash_password_file:
        return hash_password_file(Path(a.hash_password_file))
    base = Path(a.base) if a.base else Path(__file__).resolve().parents[1]
    pw = read_password(a)
    if a.check_password:   # 22차: 비밀번호 원문은 어디에도 찍지 않는다 — 까닭만
        why = weak_shared_password(pw)
        sys.stdout.write(json.dumps({"weak": bool(why), "reason": why}, ensure_ascii=False) + NL)
        return 2 if why else 0
    if a.check_start:
        # 표준 출력에는 **스크립트가 읽을 JSON 한 줄만** 둔다. 사람에게 하는 말은 표준 오류로
        # 보낸다 — 섞어 두면 콘솔 부호(cp949 등)에 막혀 읽는 쪽이 통째로 깨진다(실제로 그랬다).
        d = start_decision(a.host, base, pw, a.local_only)
        sys.stdout.write(json.dumps({k: v for k, v in d.items() if k != "reason"}, ensure_ascii=False) + NL)
        sys.stdout.flush()
        if not d["allowed"]:
            msg = NL + "[LogTriage] 이대로는 띄우지 않습니다" + NL + d["reason"] + NL
            try:
                sys.stderr.write(msg)
            except UnicodeEncodeError:
                enc = getattr(sys.stderr, "encoding", None) or "utf-8"
                sys.stderr.write(msg.encode(enc, "replace").decode(enc, "replace"))
            sys.stderr.flush()
            return 2
        return 0
    serve(a.host, a.port, base, pw, [Path(d) for d in a.allow_dir], a.db or None, a.local_only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
