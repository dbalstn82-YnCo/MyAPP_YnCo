"""바깥 링크 허용 도메인(2026-10-15 아이디어 1, GPT 31·32차 권고).

화면의 링크는 같은 출처(이 서버)이거나, https 이면서 아래 제조사·공식 문서 사이트(또는 그 하위 도메인)일 때만 이동한다.
목록에 없는 주소는 '주소만' 보여 주고 이동하지 않는다. 목록은 실행 파일에 들어 있어 판(해시)과 함께만 바뀐다 —
누군가 설정 파일 하나로 늘릴 수 없다. 사용자 글(블로그·위키·코드 저장소)은 넣지 않는다.
"""
LINK_HOSTS = (
    "docs.oracle.com", "www.oracle.com", "support.oracle.com",
    "learn.microsoft.com", "support.microsoft.com", "techcommunity.microsoft.com",
    "www.ibm.com",
    "access.redhat.com", "docs.redhat.com",
    "www.postgresql.org", "dev.mysql.com", "mariadb.com",
    "docs.altibase.com", "docs.tibero.com", "support.tibero.com", "docs.tmaxsoft.com",
    "www.cubrid.org", "manual.sunjesoft.co.kr", "www.metabuild.co.kr",
    "cwiki.apache.org", "httpd.apache.org", "tomcat.apache.org", "nginx.org",
    "docs.spring.io", "docs.wildfly.org", "docs.hibernate.org", "mybatis.org",
    "ubuntu.com", "www.suse.com", "www.hpe.com",
    "endoflife.date",
)

# 3차 아이디어 4: 서명 룰팩(manifest.yaml 의 link_hosts — 서명 범위 안)으로만 늘린다. 적용 때 검증해
# 룰팩 적용 기록 두 곳(conf/rulepack_policy.json · .rpk-transactions/policy.json)에 같이 적고, 두 곳이 같을 때만 쓴다.
_HOST = __import__("re").compile(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
_SUFFIX_ONLY = {"co.kr", "or.kr", "go.kr", "ac.kr", "re.kr", "ne.kr", "pe.kr", "com.cn", "co.jp", "co.uk", "com.au", "github.io",
                "blogspot.com", "tistory.com", "naver.com", "daum.net", "wikipedia.org", "github.com", "githubusercontent.com"}
EXTRA_MAX = 100


def validate_hosts(hosts) -> list:
    """룰팩이 더하는 도메인 — 소문자 호스트 이름만(별표·IP·포트·경로 없음), 공용 접미어·사용자 글 사이트는 거부, 100개까지."""
    if hosts in (None, ""):
        return []
    if not isinstance(hosts, list) or len(hosts) > EXTRA_MAX:
        raise ValueError(f"link_hosts 는 {EXTRA_MAX}개 이하의 목록이어야 합니다")
    out = []
    for h in hosts:
        h = str(h).strip().lower().rstrip(".")
        if not _HOST.fullmatch(h) or h.count(".") < 1 or h in _SUFFIX_ONLY or any(h.endswith("." + s) for s in ("tistory.com", "blogspot.com", "github.io")):
            raise ValueError(f"허용되지 않는 링크 도메인: {h[:60]}")
        if h not in out:
            out.append(h)
    return out


def extra_hosts(base) -> list:
    """적용 기록 두 곳이 같고 형식이 맞을 때만 — 한 파일만 고쳐서는 늘어나지 않는다."""
    import json
    from pathlib import Path as _P
    vals = []
    for p in (_P(base) / "conf" / "rulepack_policy.json", _P(base) / ".rpk-transactions" / "policy.json"):
        try:
            vals.append(json.loads(p.read_text(encoding="utf-8")).get("link_hosts") or [])
        except (OSError, ValueError, AttributeError):
            return []
    if len(vals) != 2 or vals[0] != vals[1]:
        return []
    try:
        return validate_hosts(vals[0])
    except ValueError:
        return []


# 화면 공통 링크 검사 — 같은 출처면 정규화된 주소, 허용 https 면 그 주소, 아니면 '' (이동 안 함)
OKHREF_JS = (
    # 3차 아이디어 1: 이 대본의 nonce 를 받아 두고, 대본이 만드는 <style> 요소에 단다(style-src-elem)
    "window.LT_NONCE=window.LT_NONCE||((document.currentScript&&document.currentScript.nonce)||'');"
    "window.ltStyleEl=function(){var s=document.createElement('style');if(window.LT_NONCE)s.nonce=window.LT_NONCE;return s};"
    "window.LT_LINK_HOSTS=%HOSTS%;"
    "window.LT_OKHREF=function(h){try{h=String(h==null?'':h).trim();if(!h)return'';var u=new URL(h,location.href);"
    "if(u.username||u.password)return'';"
    "if(u.origin===location.origin)return u.href;"
    "if(u.protocol!=='https:'||!/^https:\\/\\//i.test(h))return'';"
    "var n=u.hostname.toLowerCase(),H=(window.LT_LINK_HOSTS||[]).concat(window.LT_LINK_HOSTS_EXTRA||[]);"
    "for(var i=0;i<H.length;i++){if(n===H[i]||n.slice(-H[i].length-1)==='.'+H[i])return u.href}return''}catch(_){return''}};"
)


# 3차 아이디어 2: Trusted Types 기본 정책 — innerHTML 같은 HTML 대입이 모두 이 함수를 지난다(브라우저가 강제).
# 화면 값 검토(정적 시험·esc)와 겹으로 두는 마지막 울타리다. 대본 주소는 같은 출처만, 문자열 대본(eval 류)은 거부.
# GPT 37·38차: 허용 목록으로 다시 짓는다 — 우리 화면이 실제로 쓰는 태그·속성(소스에서 센 것)만 남긴다.
#   · 허용 밖 실행·원문 태그(script·style·iframe·math·foreignObject·title·noscript…)는 태그를 버리고, 그 밖의 모르는 태그는 글자로 보인다(&lt;IP&gt;).
#   · 주소(href·src)는 엔티티·제어 문자·공백을 풀어 javascript:/vbscript:/data:(이미지 외)면 뺀다.
#   · style·fill·stroke·clip-path 의 url(...) 은 #조각·data:image 만(바깥 주소로 새는 CSS 차단), expression·behavior·@import 금지.
#   · id·name 이 document·window 의 기존 속성(쿠키·함수·LT_* 전역)을 가리면 뺀다(DOM Clobbering). form 속성 이름과 겹치는 name 도 뺀다.
#   · 속성값의 < > " 는 늘 엔티티로 다시 쓴다 — textarea 같은 원문 요소 안에서 값이 태그로 되살아나지 않게(mXSS).
#   · 글 속의 맨 < > 도 엔티티로 — 남는 '<' 은 우리가 다시 지은 허용 태그뿐이다.
# (검증된 소독기 DOMPurify 반입은 외부 파일이라 승인 뒤 — 그때까지 이 규칙과 공격 벡터 시험으로 지킨다.)
TT_JS = (
    "(function(){if(!window.trustedTypes||!trustedTypes.createPolicy||trustedTypes.defaultPolicy)return;"
    r"var OKTAG=/^(div|span|b|i|u|s|em|strong|small|mark|kbd|code|pre|p|br|hr|a|button|input|label|select|option|optgroup|textarea|table|thead|tbody|tfoot|tr|td|th|col|colgroup|caption|ul|ol|li|dl|dt|dd|h[1-6]|section|aside|nav|header|footer|article|main|details|summary|dialog|time|img|figure|figcaption|sup|sub|abbr|del|ins|blockquote|q|wbr|progress|meter|fieldset|legend|svg|g|path|rect|circle|ellipse|line|polyline|polygon|text|tspan|defs|lineargradient|radialgradient|stop|clippath)$/i;"
    r"var DROP=/^(script|style|template|iframe|frame|frameset|object|embed|applet|base|meta|link|form|noscript|noembed|noframes|xmp|plaintext|listing|title|math|foreignobject|animate|animatemotion|animatetransform|set|handler|listener|portal|use|image)$/i;"
    r"var OKATTR=/^(class|style|title|id|name|href|src|alt|type|value|placeholder|checked|disabled|selected|readonly|multiple|required|colspan|rowspan|span|width|height|for|role|tabindex|target|rel|open|min|max|step|maxlength|minlength|size|rows|cols|lang|dir|hidden|datetime|spellcheck|autocomplete|inputmode|pattern|label|start|reversed|accept|download|viewbox|d|fill|stroke|stroke-width|stroke-linecap|stroke-linejoin|stroke-dasharray|stroke-dashoffset|stroke-opacity|stroke-miterlimit|fill-opacity|fill-rule|clip-rule|clip-path|x|y|x1|y1|x2|y2|cx|cy|r|rx|ry|fx|fy|dx|dy|points|offset|stop-color|stop-opacity|gradientunits|gradienttransform|transform|opacity|preserveaspectratio|text-anchor|font-size|font-weight|font-family|letter-spacing|dominant-baseline|focusable|vector-effect|shape-rendering|(data|aria)-[a-z0-9_.:-]+)$/i;"
    r"var CSSATTR=/^(style|fill|stroke|clip-path)$/i;"
    r'''var ENT={colon:':',tab:'\t',newline:'\n',nbsp:' ',lpar:'(',rpar:')',sol:'/',period:'.',comma:',',amp:'&',quot:'\x22',apos:"'"};'''
    r"function dec(v){return v.replace(/&#x([0-9a-f]+);?/gi,function(_,h){return String.fromCharCode(parseInt(h,16)||0)})"
    r".replace(/&#(\d+);?/g,function(_,d){return String.fromCharCode(+d||0)})"
    r".replace(/&([a-z]+);/gi,function(a,n){return ENT[n.toLowerCase()]||a})"
    r".replace(/[\x00-\x20\x7f-\xa0]|\s/g,'').toLowerCase()}"
    r"function badUrl(v){var d=dec(v);return /^(javascript|vbscript|livescript|mocha):/.test(d)||(/^data:/.test(d)&&!/^data:image\/(png|gif|jpe?g|webp|svg\+xml)[;,]/.test(d))}"
    r"function badCss(v){var d=dec(v).replace(/\\([0-9a-f]{1,6})/g,function(_,h){return String.fromCharCode(parseInt(h,16)||0)}).replace(/\\/g,'');return /expression\(|javascript:|vbscript:|behavior:|-moz-binding|@import/.test(d)||/url\((?!['\x22]?(#|data:image\/(png|gif|jpe?g|webp|svg\+xml)[;,]))/.test(d)}"
    r"var D=typeof document!=='undefined'?document:{},EL=typeof Element!=='undefined'?Element:null,HC=typeof HTMLCollection!=='undefined'?HTMLCollection:null,"
    r"FP=typeof HTMLFormElement!=='undefined'?HTMLFormElement.prototype:{};"
    r"function isNode(o){return !!(o&&((EL&&o instanceof EL)||(HC&&o instanceof HC)))}"
    r"function clob(n,v){v=String(v).trim();if(!v)return false;if(/^(LT_|lt[A-Z])/.test(v))return true;"
    r"try{if(v in D&&!isNode(D[v]))return true;if(v in window&&!isNode(window[v]))return true;if(n==='name'&&v in FP)return true}catch(e){return true}return false}"
    r"function txt(t){return t.replace(/</g,'&lt;').replace(/>/g,'&gt;')}"
    r"function q(v){return '\x22'+v.replace(/\x22/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;')+'\x22'}"
    r"function tag(t){var m=/^<\s*(\/?)\s*([a-z][a-z0-9:-]*)/i.exec(t);if(!m)return txt(t);"
    r"var nm=m[2],lo=nm.toLowerCase();if(DROP.test(lo))return '';if(!OKTAG.test(lo))return txt(t);if(m[1])return '</'+nm+'>';"
    r"var end=/\/\s*>$/.test(t)?'/>':'>',body=t.slice(m[0].length,t.length-1),out='<'+nm,x,"
    r"""re=/([\s\/]+)([^\s=\/>"']+)(\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g;"""
    r"""while((x=re.exec(body))){var n=x[2].toLowerCase(),a=x[4]||'',v=/^["']/.test(a)?a.slice(1,-1):a;"""
    r"if(n==='xmlns'){if(dec(v)==='http://www.w3.org/2000/svg')out+=' xmlns='+q('http://www.w3.org/2000/svg');continue}"
    r"if(!OKATTR.test(n))continue;"
    r"if((n==='id'||n==='name')&&clob(n,v))continue;"
    r"if((n==='href'||n==='src')&&badUrl(v))continue;"
    r"if(CSSATTR.test(n)&&badCss(v))continue;"
    r"out+=' '+x[2]+(x[3]?'='+q(v):'')}"
    r"return out+end}"
    r"""function clean(s){return String(s).replace(/<!--[\s\S]*?-->|<(?:[^>"']|"[^"]*"|'[^']*')*>|[<>]/g,function(t){"""
    r"return t==='>'?'&gt;':t==='<'?'&lt;':t.slice(0,4)==='<!--'?'':tag(t)})}"
    "try{trustedTypes.createPolicy('default',{createHTML:clean,"
    "createScriptURL:function(u){var x=new URL(u,location.href);if(x.origin===location.origin)return x.href;throw new TypeError('LogTriage: 바깥 대본 주소 거부')},"
    "createScript:function(){throw new TypeError('LogTriage: 문자열 대본 거부')}})}catch(e){}})();"
)


def okhref_js() -> str:
    import json
    return OKHREF_JS.replace("%HOSTS%", json.dumps(list(LINK_HOSTS)))
