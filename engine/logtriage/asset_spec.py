# -*- coding: utf-8 -*-
"""자산 기준 항목 — 우리가 요구하는 것 (2026-09-29)

사용자 지시: "템플릿을 요청하는 게 아니라 **반드시 필요한 항목과 정보를 요구**해야 한다.
그렇기에 우리가 기준이 되어야 한다."

그래서 이 표는 엑셀 칸 위치(A·B·C…)가 아니라 **뜻**으로 항목을 정의한다.
항목마다 `why` 를 단다 — 그 항목이 없을 때 **장애 때 무엇을 못 하는지**. 그 답이 없는 항목은
요구하지 않는다. 그것이 '우리가 기준' 이라는 말의 내용이다.

비밀번호는 받지 않는다. 계정 이름은 받되(누구로 붙는지 알아야 하므로) 비밀번호는 어떤 유형에도
칸을 두지 않고, 남의 문서에서 들어와도 버린다(`DROP`). 자산 대장은 여러 사람이 보고 내려받는
문서이고, 거기에 평문 비밀번호를 모으는 것은 그 자체가 사고다.

**우리가 할 수 있는 약속 (SECRET_CONTRACT)**

  · 자격 정보를 **보관하는 기능을 두지 않는다** — 비밀번호 칸을 어떤 유형에도 만들지 않고,
    사용자가 그런 항목을 만들려 해도 거절한다.
  · 자격 정보임을 **알아볼 수 있는** 머리글과 값 표기는 읽는 자리에서 막는다.
  · 다만 뜻 표시 없이 일반 글자 칸에 적힌 비밀값까지 완전히 판별하는 것은 **보장하지 않는다.**
    'Admin1234' 가 비밀번호인지 장비 이름인지 임시 코드인지 문자열만 보고 정할 방법이 없다.
    무작위해 보이는지(엔트로피)로도 안 된다 — UUID·일련번호·인증서 지문이 똑같이 생겼다.

세 번째 줄을 적어 두는 것이 중요하다. 지킬 수 없는 약속을 적어 두면, 그 약속을 믿고
사람들이 비밀번호를 적어 넣는다.

`aliases` 는 남이 준 엑셀·한글 표의 머리글을 우리 항목에 맞출 때 쓰는 사전이고,
`kind` 는 값 모양(IP·날짜·숫자)으로 넘겨짚을 때 쓴다.
"""
from __future__ import annotations

SECRET_CONTRACT = (
    "자격 정보를 보관하는 기능을 두지 않고, 자격 정보임을 알아볼 수 있는 머리글·값 표기는"
    " 읽는 자리에서 막습니다. 다만 뜻 표시 없이 일반 글자 칸에 적힌 비밀값까지 완전히"
    " 판별하는 것은 보장하지 않습니다 — 'Admin1234' 가 비밀번호인지 장비 이름인지는"
    " 글자만 보고 정할 수 없습니다. 비밀번호·키는 금고에 두십시오."
)

SPEC_VERSION = "2"
# 기준의 판(SPEC_VERSION)과 항목 id 는 다른 것이다. **id 는 바뀌지 않는다** — 판이 올라가도
# 이미 등록된 자산이 깨지지 않게 한다. 등급이 올라가 필수가 비게 된 자산은 지우거나 막지 않고
# '확인 필요' 로만 표시한다(GPT 교차 판단).

# 등급 — 요구의 세기
LEVEL = {
    "required": "필수",      # 없으면 장애 대응이 막힌다. 비면 [미완성] 으로 표시한다
    "conditional": "조건부 필수",   # 같은 묶음에서 **하나는** 있어야 한다(아래 ONE_OF)
    "advised": "권장",       # 없으면 대응이 느려진다
    "optional": "선택",      # 있으면 좋다
}

# 조건부 필수 묶음 — "이 중 하나는 있어야 한다".
# 'IP 필수' 로 적으면 NAT·VIP·DNS·URL 환경에서 거짓 값을 채우게 된다(GPT 교차 판단).
ONE_OF = {
    "reach": {"label": "접속할 수 있는 주소",
              "why": "장애가 나도 그 대상에 닿을 방법이 없습니다",
              "fields": ["mgmt_ip", "fqdn", "console"]},
    "identify": {"label": "로그와 이을 이름",
                 "why": "로그에 찍힌 이름과 이 자산을 이을 수 없어, 장애가 나도 어느 자산인지"
                        " 자동으로 찾지 못합니다",
                 "fields": ["hostname", "instance"]},
    "observe": {"label": "로그를 볼 곳",
                "why": "장애 원인을 확인할 자료가 어디 있는지 알 수 없습니다",
                "fields": ["log_path", "log_channel"]},
}

# 절대 받지 않는 것 — 들어와도 버린다(세어서 알려 주기만 한다)
DROP = {
    "password": {
        "label": "비밀번호",
        "why": "자산 대장은 여러 사람이 보고 내려받는 문서입니다. 평문 비밀번호를 여기에 모으면"
               " 대장 유출이 곧 전 장비 탈취가 됩니다. 계정 이름만 받고, 비밀번호는 금고에 두십시오.",
        "aliases": ["비밀번호", "비번", "초기비번", "초기비밀번호", "패스워드", "암호", "비밀 번호",
                    "암호문", "복호화", "비밀", "새비번", "임시비번", "변경전비번", "비밀번",
                    "password", "passwd", "pword", "pwd", "pw", "pass word", "passphrase",
                    "passcode", "otp", "pin"],
    },
    "key": {
        "label": "키·토큰",
        "why": "열쇠는 비밀번호와 같습니다 — 대장에 모으면 유출 한 번으로 전부 열립니다.",
        "aliases": ["apikey", "api key", "accesskey", "access key", "secretkey", "secret key",
                    "privatekey", "private key", "개인키", "비밀키", "인증키", "인증값", "토큰",
                    "token", "communitystring", "community string", "snmp community",
                    "keystore", "truststore", "keyfile", "pem", "pfx", "p12", "jks",
                    "sshkey", "ssh key", "지문", "fingerprint", "salt", "seed", "nonce",
                    "clientsecret", "client secret", "refreshtoken", "bearer"],
    },
    "mixed": {
        "label": "뜻이 섞인 자격 정보",
        "why": "이 열에는 계정과 비밀번호가 함께 들어 있을 수 있습니다. 아이디만 살리려고 칸 안을"
               " 갈라 보는 순간 비밀번호를 읽게 되므로, 열째로 받지 않습니다."
               " 계정과 비밀번호를 다른 열로 나눠 주시면 계정만 받겠습니다.",
        "aliases": ["계정정보", "인증정보", "로그인정보", "접속정보", "계정및비번", "아이디비번",
                    "idpw", "id pw", "id/pw", "userpw", "user pw", "acctpw",
                    "credential", "credentials", "cred", "secret", "자격증명", "자격정보",
                    "인증", "로그인", "login", "auth", "signin", "sign in", "비밀정보",
                    # 접속 문자열에는 대개 비밀번호가 박혀 있다(user=x;password=y) — 열째로 받지 않는다.
                    # 낱말을 붙인 꼴만 적어 'JDBC 드라이버 버전' 같은 정상 열은 살린다(GPT 10차)
                    "접속문자열", "연결문자열", "접속스트링", "connectionstring", "connstring",
                    "connectionuri", "datasourceurl", "jdbcurl", "odbcdsn", "dburl"],
    },
}

# 공통 항목 — 유형과 상관없이 요구한다
COMMON = [
    # ── 무엇인가 ──────────────────────────────────────────────────────────
    dict(id="asset_id", label="자산 ID", group="기본", level="required", kind="text",
         why="여러 문서와 시스템에서 같은 장비를 같은 것으로 부를 수 없습니다",
         example="SRV-0142", aliases=["자산id", "자산번호", "구성id", "관리번호", "자산코드",
                                      "ci id", "asset id", "assetid", "id"]),
    dict(id="name", label="자산명", group="기본", level="required", kind="text",
         why="사람이 부를 이름이 없어 인수인계와 통화에서 서로 다른 것을 가리킵니다",
         example="대외계 WAS 1호기", aliases=["자산명", "구성자원명", "장비명", "시스템명",
                                              "자원명", "name", "asset name"]),
    dict(id="type", label="유형", group="기본", level="required", kind="choice",
         choices=["server", "dbms", "web", "was", "network", "sw"],
         choice_ko={"server": "서버", "dbms": "DBMS", "web": "WEB", "was": "WAS",
                    "network": "네트워크", "sw": "SW·솔루션"},
         why="어떤 규칙과 절차를 댈지 정하지 못합니다",
         example="was", aliases=["유형", "구분", "종류", "분류", "type", "category"]),
    dict(id="site", label="사이트·센터", group="기본", level="required", kind="text",
         why="어디 일인지, 누가 볼 수 있는지를 가르지 못합니다",
         example="본사 IDC", aliases=["사이트", "센터", "관리센터", "지사", "location site",
                                      "site", "region"]),
    dict(id="service", label="서비스(업무)명", group="기본", level="required", kind="text",
         why="이 장비가 죽으면 **무슨 업무가 멈추는지** 모릅니다 — 보고와 우선순위의 근거입니다",
         example="인터넷뱅킹 조회", aliases=["서비스명", "업무명", "업무", "서비스", "시스템명",
                                             "service", "business"]),
    dict(id="criticality", label="중요도", group="기본", level="required", kind="choice",
         choices=["high", "mid", "low"], choice_ko={"high": "상", "mid": "중", "low": "하"},
         # 뜻을 적어 두지 않으면 사이트마다 '상' 이 다른 것을 가리킨다(GPT 교차 판단)
         choice_why={"high": "장애 시 핵심 업무 중단 또는 대규모 사용자 영향",
                     "mid": "업무 영향은 있으나 우회·부분 운영 가능",
                     "low": "제한적 영향 또는 비운영 보조 자산"},
         why="둘이 동시에 죽었을 때 무엇부터 살릴지 정하지 못합니다",
         example="high", aliases=["중요도", "등급", "우선순위", "criticality", "priority",
                                  "grade", "tier"]),
    dict(id="env", label="운영 환경", group="기본", level="required", kind="choice",
         choices=["prod", "stage", "dev", "test"],
         choice_ko={"prod": "운영", "stage": "검증", "dev": "개발", "test": "시험"},
         why="운영 장애인지 개발·검증계 장애인지 몰라 대응 강도를 잘못 잡습니다",
         example="prod", aliases=["환경", "운영환경", "env", "environment", "구분(환경)",
                                  "stage", "zone"]),
    dict(id="state", label="운영 상태", group="기본", level="required", kind="choice",
         choices=["active", "standby", "maintenance", "retired"],
         choice_ko={"active": "가동", "standby": "대기", "maintenance": "정비", "retired": "폐기"},
         why="죽어 있어야 정상인 대기·정비 장비나 이미 폐기한 장비를 장애로 잡습니다",
         example="active", aliases=["상태", "운영상태", "가동상태", "state", "status",
                                    "사용여부", "운용상태"]),
    dict(id="subtype", label="세부 종류", group="기본", level="optional", kind="text",
         why="같은 'SW' 라도 API 게이트웨이와 배치 도구는 보는 곳이 다릅니다",
         example="api_gateway", aliases=["세부유형", "소분류", "subtype", "세부종류"]),
    # ── 누구에게 ──────────────────────────────────────────────────────────
    dict(id="owner_team", label="운영 책임 조직", group="담당", level="required", kind="text",
         # 사람은 퇴사·이동·휴가로 빨리 낡는다 — 책임 주체는 조직이다(GPT 교차 판단)
         why="장애가 났을 때 누가 판단하고 조치해야 하는지 이어지지 않습니다."
             " 개인은 바뀌지만 조직은 남습니다",
         example="DB운영팀", aliases=["담당팀", "운영팀", "책임조직", "부서", "팀",
                                      "owner team", "team", "group"]),
    dict(id="owner1", label="1차 담당자", group="담당", level="advised", kind="text",
         why="조직은 알아도 지금 당장 누구에게 전화할지 모릅니다",
         example="김운영 / 010-0000-0000", aliases=["담당자", "1차 담당", "운영담당", "관리자",
                                                    "owner", "primary contact", "담당"]),
    dict(id="owner2", label="2차 담당자(엔지니어)", group="담당", level="advised", kind="text",
         why="1차가 못 풀 때 넘길 곳이 없습니다",
         example="박엔지 / 010-0000-0000", aliases=["2차 담당", "엔지니어", "기술담당",
                                                    "secondary contact"]),
    dict(id="vendor_contact", label="제조사·유지보수 연락처", group="담당", level="advised",
         kind="text", why="3차로 넘길 곳이 없어 제조사 판단이 필요한 장애에서 멈춥니다",
         example="○○테크 02-000-0000", aliases=["제조사", "유지보수업체", "벤더", "협력사",
                                                 "vendor", "maintenance", "support contact"]),
    dict(id="maint_until", label="유지보수 만료일", group="담당", level="advised", kind="date",
         why="지금 제조사를 부를 수 있는 상태인지 모릅니다",
         example="2027-03-31", aliases=["유지보수 만료", "계약만료", "유지보수기간", "maintenance until",
                                        "contract end", "warranty"]),
    dict(id="service_hours", label="서비스 시간", group="담당", level="advised", kind="text",
         why="지금 재기동해도 되는 시간인지 판단하지 못합니다",
         example="평일 09-18 / 24x365", aliases=["서비스시간", "운영시간", "가동시간",
                                                 "service hours", "operating hours"]),
    # ── 어디로 붙는가 ─────────────────────────────────────────────────────
    dict(id="hostname", label="호스트명", group="접속", level="conditional", one_of="identify",
         kind="text",
         why="**로그에 찍히는 이름**입니다. 이것이 없으면 분석 결과와 이 장비를 이을 수 없어,"
             " 장애가 나도 어느 자산인지 자동으로 찾지 못합니다"
             "(인스턴스명으로 대신할 수 있습니다)",
         example="was01", aliases=["호스트명", "호스트", "hostname", "host", "노드명", "서버명",
                                   "node", "machine name", "computer name"]),
    dict(id="mgmt_ip", label="관리 IP", group="접속", level="conditional", one_of="reach",
         kind="ip",
         why="어디로 접속해야 하는지 모릅니다(이름·콘솔 주소로 대신할 수 있습니다)",
         example="10.10.1.21", aliases=["ip", "관리ip", "ip주소", "management ip", "mgmt ip",
                                        "주소", "ip address"]),
    dict(id="fqdn", label="접속 이름(FQDN·URL)", group="접속", level="conditional", one_of="reach",
         kind="text",
         why="IP 가 바뀌거나 VIP·DNS 로 도는 환경에서는 이름이 유일한 접속 경로입니다",
         example="was01.example.com", aliases=["fqdn", "도메인", "url", "주소(이름)", "hostname(fqdn)",
                                               "dns", "접속주소"]),
    dict(id="service_ip", label="서비스 IP", group="접속", level="advised", kind="ip",
         why="사용자가 닿는 경로와 우리가 붙는 경로를 구분하지 못합니다",
         example="10.20.1.21", aliases=["서비스ip", "vip", "service ip", "대표ip"]),
    dict(id="port", label="서비스 포트", group="접속", level="advised", kind="text",
         why="무엇이 떠 있어야 정상인지 모릅니다",
         example="8080, 8443", aliases=["포트", "port", "service port", "listen port"]),
    dict(id="access", label="접속 방법", group="접속", level="advised", kind="text",
         why="어떻게 붙는지(SSH·RDP·콘솔) 몰라 첫 걸음이 늦습니다",
         example="SSH 22", aliases=["접속방법", "접속", "원격접속", "access", "protocol",
                                    "connection"]),
    dict(id="account", label="접속 계정", group="접속", level="advised", kind="text",
         why="어느 계정으로 붙는지 몰라 권한 문제로 되돌아옵니다",
         note="비밀번호는 받지 않습니다 — 계정 이름만.",
         example="oper", aliases=["계정", "사용자", "id", "account", "user", "username",
                                  "login"]),
    dict(id="console", label="원격 콘솔(iLO·iDRAC 등)", group="접속", level="advised", kind="text",
         why="OS 가 죽으면 손댈 방법이 없습니다 — 그때 유일한 길입니다",
         example="10.10.9.21", aliases=["콘솔", "ilo", "idrac", "bmc", "kvm", "remote console",
                                        "ipmi"]),
    dict(id="location", label="물리 위치(랙·상면)", group="접속", level="optional", kind="text",
         why="직접 가야 할 때 어디로 갈지 모릅니다",
         example="A동 3층 R-12 / 21U", aliases=["위치", "설치위치", "랙", "상면", "rack",
                                                "location", "물리위치"]),
    # ── 무엇이 돌고 있는가 ────────────────────────────────────────────────
    dict(id="os", label="OS 종류·버전", group="소프트웨어", level="advised", kind="text",
         why="판정 규칙과 에러코드가 제품·버전에 걸립니다 — 없으면 엉뚱한 조치를 댑니다",
         example="RHEL 8.8", aliases=["os", "운영체제", "os버전", "operating system", "플랫폼"]),
    dict(id="product", label="제품·버전", group="소프트웨어", level="advised", kind="text",
         why="같은 에러코드라도 버전마다 조치가 다릅니다",
         example="JEUS 8 Fix#5", aliases=["제품", "제품명", "버전", "솔루션", "product",
                                          "version", "sw", "소프트웨어"]),
    dict(id="log_path", label="로그 경로", group="소프트웨어", level="conditional", one_of="observe",
         kind="text",
         why="**우리가 어디서 로그를 가져오는지** 모릅니다 — 자동 수집·분석이 서지 않습니다",
         example="/app/jeus/logs", aliases=["로그경로", "로그위치", "log path", "log dir",
                                            "로그", "logpath"]),
    dict(id="log_channel", label="로그를 보는 다른 방법", group="소프트웨어", level="conditional",
         one_of="observe", kind="text",
         # 파일 경로만 생각하면 Windows 이벤트 로그·DB alert log·중앙 수집에 맞지 않는다(GPT 교차 판단)
         why="Windows 이벤트 로그나 중앙 수집처럼 파일 경로가 아닌 자산은 볼 곳이 없어집니다",
         example="Windows 이벤트 로그 / System",
         aliases=["이벤트로그", "event log", "syslog", "수집방법", "로그수집", "로그채널"]),
    dict(id="install_path", label="설치 경로", group="소프트웨어", level="advised", kind="text",
         why="설정 파일을 어디서 찾을지 몰라 조치가 늦습니다",
         example="/app/jeus", aliases=["설치경로", "홈디렉터리", "install path", "home"]),
    dict(id="start_stop", label="기동·정지 방법", group="소프트웨어", level="advised",
         kind="multiline",
         why="1차 조치의 첫 단계가 바로 이것입니다 — 없으면 아무나 손댈 수 없습니다",
         example="systemctl restart jeus", aliases=["기동", "정지", "재기동", "구동방법",
                                                    "start", "stop", "restart"]),
    dict(id="patch_level", label="패치 수준", group="소프트웨어", level="advised", kind="text",
         why="이미 고쳐진 결함을 다시 쫓게 됩니다",
         example="2026-06 누적", aliases=["패치", "패치수준", "fix", "patch level", "sp"]),
    dict(id="eos", label="지원 종료일(EOS)", group="소프트웨어", level="advised", kind="date",
         why="제조사가 더는 받아 주지 않는 장비를 3차로 넘기게 됩니다",
         example="2028-12-31", aliases=["eos", "eol", "지원종료", "단종", "end of support"]),
    # ── 무엇과 얽혀 있는가 ────────────────────────────────────────────────
    dict(id="ha", label="이중화 구성", group="연계", level="advised", kind="text",
         why="지금 재기동해도 되는지 판단하지 못합니다 — 단독이면 재기동이 곧 중단입니다",
         example="Active-Standby (짝: was02)", aliases=["이중화", "ha", "클러스터", "cluster",
                                                        "redundancy", "구성"]),
    dict(id="upstream", label="상위 연계", group="연계", level="advised", kind="text",
         why="이 장비가 무엇에 기대고 있는지 몰라 원인을 위에서 찾지 못합니다",
         example="DB: ora-prd-01", aliases=["상위", "연계시스템", "의존", "upstream",
                                            "depends on"]),
    dict(id="downstream", label="하위 연계", group="연계", level="advised", kind="text",
         why="이게 죽으면 무엇이 같이 죽는지 몰라 영향 범위를 못 적습니다",
         example="대외계 게이트웨이", aliases=["하위", "영향", "downstream", "affects"]),
    dict(id="backup", label="백업 방식·주기", group="연계", level="advised", kind="text",
         why="되돌릴 수 있는지 모른 채 위험한 조치를 하게 됩니다",
         example="일 1회 전체 / 보관 30일", aliases=["백업", "backup", "백업주기", "백업정책"]),
    # ── 이 정보 자체를 믿을 수 있는가 ──────────────────────────────────────
    dict(id="verified_at", label="최종 확인일", group="정보", level="advised", kind="date",
         why="이 자산 정보가 지금도 믿을 만한지 판단할 수 없습니다 — 낡은 대장은 없는 것보다 위험합니다",
         example="2026-09-30", aliases=["확인일", "최종확인", "갱신일", "updated", "verified",
                                        "점검일"]),
    dict(id="source", label="정보 출처", group="정보", level="advised", kind="choice",
         choices=["manual", "file", "api", "discovered"],
         choice_ko={"manual": "직접 입력", "file": "파일에서", "api": "연동", "discovered": "자동 탐지"},
         why="틀린 정보가 어디서 들어왔는지 되짚을 수 없습니다",
         example="file", aliases=["출처", "source", "입력방법", "등록경로"]),
]

# 유형별로 더 요구하는 것
BY_TYPE = {
    "dbms": [
        dict(id="instance", label="인스턴스·SID", group="유형", level="required", kind="text",
             why="어느 인스턴스 장애인지 가리키지 못합니다",
             example="ORAPRD", aliases=["sid", "인스턴스", "instance", "db name", "서비스명"]),
        dict(id="db_port", label="DB 포트", group="유형", level="advised", kind="text",
             why="장애 때 가장 먼저 하는 것이 포트가 열려 있는지 보는 일입니다 — 번호를 모르면 그것부터 찾아야 합니다", example="1521",
             aliases=["db포트", "포트", "listener port", "db port"]),
        dict(id="archive_mode", label="아카이브 모드", group="유형", level="advised", kind="text",
             why="아카이브 여부에 따라 어느 시점까지 되돌릴 수 있는지가 달라집니다 — 모르면 복구 계획을 세울 수 없습니다", example="ARCHIVELOG",
             aliases=["아카이브", "archive", "archivelog", "로그모드"]),
        dict(id="data_path", label="데이터 파일 위치", group="유형", level="advised", kind="text",
             why="용량 장애에서 어디를 봐야 하는지 모릅니다", example="/oradata",
             aliases=["데이터경로", "데이터파일", "data path", "datafile"]),
    ],
    "was": [
        dict(id="instance", label="인스턴스명", group="유형", level="required", kind="text",
             why="한 장비에 여러 개가 뜹니다 — 어느 것인지 가리켜야 합니다",
             example="container1", aliases=["인스턴스", "instance", "노드", "도메인"]),
        dict(id="heap", label="힙·메모리 설정", group="유형", level="advised", kind="text",
             why="OOM 판정에서 정상 범위를 모릅니다", example="-Xms2g -Xmx4g",
             aliases=["힙", "heap", "메모리", "jvm", "xmx"]),
        dict(id="pool", label="연결 풀 설정", group="유형", level="advised", kind="text",
             why="연결 고갈 장애에서 한계값을 모릅니다", example="max 100",
             aliases=["커넥션풀", "connection pool", "pool", "dbcp"]),
    ],
    "web": [
        dict(id="instance", label="인스턴스·가상호스트", group="유형", level="required", kind="text",
             why="한 장비에 여러 사이트가 뜹니다 — 어느 것인지 가리켜야 합니다",
             example="www.example.com", aliases=["인스턴스", "가상호스트", "vhost", "instance",
                                                 "도메인"]),
        dict(id="doc_root", label="문서 루트", group="유형", level="advised", kind="text",
             why="배포·권한 장애에서 어디를 볼지 모릅니다", example="/var/www/html",
             aliases=["document root", "docroot", "문서루트", "웹루트"]),
    ],
    "network": [
        dict(id="device_kind", label="장비 종류", group="유형", level="required", kind="text",
             why="스위치·방화벽·L4 는 보는 곳이 다릅니다", example="L4 스위치",
             aliases=["장비종류", "device type", "모델", "model", "기종"]),
        dict(id="redundancy", label="이중화 프로토콜", group="유형", level="advised", kind="text",
             why="절체가 됐는지 판단하지 못합니다", example="VRRP",
             aliases=["vrrp", "hsrp", "이중화프로토콜", "redundancy protocol"]),
    ],
    "sw": [
        dict(id="vendor", label="공급사", group="유형", level="required", kind="text",
             why="솔루션 장애는 대개 우리 손을 벗어납니다 — 공급사를 모르면 3차로 넘길 곳 자체가 없습니다", example="○○소프트",
             aliases=["공급사", "제조사", "vendor", "manufacturer", "supplier"]),
        dict(id="contract", label="계약 번호", group="유형", level="advised", kind="text",
             why="기술지원을 받을 때 매번 찾아야 합니다", example="C-2026-0031",
             aliases=["계약번호", "contract", "계약", "so번호"]),
        dict(id="support_contact", label="기술지원 연락처", group="유형", level="advised",
             kind="text", why="야간·휴일에 제조사를 부를 창구를 그때 찾기 시작하면 이미 늦습니다", example="1588-0000",
             aliases=["기술지원", "support", "헬프데스크", "지원연락처"]),
    ],
    "server": [],
}

# 유형이 정해질 때 **올려 받는** 공통 항목.
# 공통에서 못 박으면 맞지 않는 유형에서 거짓 값을 부르고, 공통에서 빼면 맞는 유형에서 놓친다.
TYPE_REQUIRE = {
    "server":  {"os": "required", "hostname": "required"},
    "dbms":    {"product": "required", "db_port": "required"},
    "was":     {"product": "required", "port": "required"},
    "web":     {"product": "required", "port": "required"},
    "network": {"product": "required"},          # NOS·펌웨어 버전
    "sw":      {"product": "required"},
}

GROUP_ORDER = ["기본", "담당", "접속", "소프트웨어", "연계", "정보", "유형"]


def types() -> dict:
    """우리가 다루는 자산 유형."""
    f = next(x for x in COMMON if x["id"] == "type")
    return dict(f["choice_ko"])


def fields(asset_type: str = "", extra=None, levels=None) -> list[dict]:
    """그 유형에서 요구하는 항목 전부 — 공통 + 유형별 + **현장이 더한 것**.

    extra  : 사용자가 만든 항목 목록(asset_custom)
    levels : 기본 항목의 등급을 현장이 바꾼 것 {항목id: 등급}

    기준은 단정 짓지 않는다 — 코드에 둔 것은 '우리가 대는 최소한' 이고, 현장이 더하고
    올리고 내릴 수 있다. 다만 **항목 id 는 바뀌지 않는다**(이미 등록된 자산이 깨지지 않게).
    """
    out = [dict(f) for f in COMMON]
    for f in BY_TYPE.get(asset_type or "", []):
        out.append(dict(f))
    # 유형이 정해졌을 때만 올려 받는다(현장 조정이 이 위에 다시 얹힌다)
    for f in out:
        lv = TYPE_REQUIRE.get(asset_type or "", {}).get(f["id"])
        if lv in LEVEL and f["level"] != lv:
            f["level"] = lv
            f["level_by_type"] = True
    for f in (extra or []):
        g = dict(f)
        g.setdefault("group", "현장 항목")
        g["custom"] = True
        g.pop("one_of", None)          # 묶음은 기본 기준만 정한다
        out.append(g)
    if levels:
        for f in out:
            lv = levels.get(f["id"])
            if lv in LEVEL:
                f["level"] = lv
                f["level_changed"] = True
    order = GROUP_ORDER + ["현장 항목"]
    out.sort(key=lambda f: (order.index(f["group"]) if f["group"] in order else 99))
    return out


def spec(asset_type: str = "", extra=None, levels=None) -> dict:
    """화면·파서가 함께 쓰는 한 벌."""
    fs = fields(asset_type, extra, levels)
    ids = {f["id"] for f in fs if f["level"] == "conditional"}
    return {"version": SPEC_VERSION, "type": asset_type or "", "types": types(),
            "contract": SECRET_CONTRACT,
            "levels": LEVEL, "groups": GROUP_ORDER + ["현장 항목"], "fields": fs,
            "custom_count": sum(1 for f in fs if f.get("custom")),
            "required": [f["id"] for f in fs if f["level"] == "required"],
            "one_of": {k: {"label": v["label"], "why": v["why"],
                           "fields": [i for i in v["fields"] if i in ids]}
                       for k, v in ONE_OF.items()
                       if any(i in ids for i in v["fields"])},
            "never": {k: {"label": v["label"], "why": v["why"]} for k, v in DROP.items()}}


# 칸 안에서 '이름 = 값' 꼴로 나타나는 자격 정보 이름 — 머리글 사전과 **한 곳에서** 관리한다.
# 따로 두면 한쪽만 늘리는 회귀가 생긴다(GPT 11차). asset_import 가 이 목록으로 정규식을 만든다.
LEXICON = (
    "password", "passwd", "pwd", "pw", "passphrase", "passcode",
    "token", "access token", "accesstoken", "refresh token", "refreshtoken", "id token",
    "secret", "client secret", "clientsecret", "apikey", "api key", "api-key",
    "private key", "privatekey", "accountkey", "account key",
    "sharedaccesskey", "shared access key", "sharedaccesssignature", "sas token", "sastoken",
    "community", "snmp community", "credential", "credentials",
    "비밀번호", "비번", "암호", "토큰", "비밀키", "개인키", "인증키", "자격증명",
)

SHORT = 3          # 이 길이까지는 '낱말이 딱 맞을 때만' 버린다

# 낱말 경계 — 한글 음절 영역을 직접 적는다(글자 범위를 escape 로 적으면 판마다 어긋난다)
HANGUL_SPLIT = __import__('re').compile('[^0-9A-Za-z' + chr(0xAC00) + '-' + chr(0xD7A3) + ']+')
WORD_PARTS = __import__('re').compile(
    '[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|[0-9]+|[' + chr(0xAC00) + '-' + chr(0xD7A3) + ']+')


def _tokens(header) -> set:
    """머리글을 낱말로 쪼갠다 — 짧은 말(PW·OTP·PIN)을 안전하게 잡기 위해서.

    정규화한 글자에 그냥 '들어 있는지' 로 보면 'pw' 가 'Shipping' 을 잡는다. 반대로 거짓 양성이
    무서워 짧은 말을 아예 안 넣으면 자격 정보 열이 그대로 읽힌다 — 그쪽이 더 위험하다.
    그래서 짧은 말은 낱말 단위로만 본다. 쪼개기는 원본에서 하므로 'ＰＷ'(전각)·'P.W'·'PW(초기)'
    모두 같은 낱말이 된다.
    """
    import re as _re
    import unicodedata
    t = unicodedata.normalize("NFKC", str(header or ""))
    t = "".join(ch for ch in t if ch not in "\u200b\u200c\u200d\ufeff")
    out = set()
    # 기호를 다 뗀 몸통도 낱말로 본다 — 'P.W'·'P W' 가 쪼개지며 'pw' 를 잃지 않게
    whole = "".join(ch for ch in t if ch.isalnum()).casefold()
    if whole:
        out.add(whole)
    for w in _re.split(HANGUL_SPLIT, t):
        if not w:
            continue
        out.add(w.casefold())
        # 붙여 쓴 경계도 낱말로 본다 — 'svrPW' 의 PW, 'dbPwd' 의 Pwd, '비번1' 의 비번.
        # 대문자 뭉치(PW)·대문자+소문자(Shipping·Pwd)·소문자·숫자·한글을 따로 끊는다.
        for part in _re.findall(WORD_PARTS, w):
            out.add(part.casefold())
    return out


def _has_hangul(t) -> bool:
    return any("\uac00" <= ch <= "\ud7a3" or "\u3131" <= ch <= "\u318e" for ch in str(t or ""))


# 한글 어근은 합성어 안에서도 잡는다 — '접속암호'·'계정비번'·'개인키값' 이 낱말 일치로는 안 걸린다.
# 영문 짧은 말을 같은 식으로 보면 'pw' 가 'Shipping' 을 잡으므로 영문만 낱말로 본다(GPT 10차 상①).
def _alias_hits(na: str, h: str, toks: set, hangul: bool) -> bool:
    if hangul:
        return na in h
    if len(na) <= SHORT:
        return na in toks
    return na in h


_INDEX = {"key": None, "rows": ()}


def _drop_index():
    """(갈래, 낱말, 정규화한 낱말, 한글인가) 표 — **한 번만 만든다.**

    머리글 하나를 볼 때마다 낱말 120개를 돌며 한글 여부를 따지고 있었다. 48열이면 5,760번이다.
    목록이 바뀌면 다시 만든다 — 바뀌었는지는 각 갈래의 목록 객체와 길이로 본다.
    """
    # **내용 자체**를 열쇠로 본다. 목록 객체의 id·길이로 보면 하나 빼고 하나 넣은 경우를 놓친다 —
    # 보안 판정에서는 빠른 것보다 **정책이 바뀌면 바로 반영되는 것**이 먼저다(GPT 지적).
    # 글자 비교라 값싸다(파이썬은 글자의 해시를 들고 있다).
    key = tuple((k, tuple(d["aliases"])) for k, d in DROP.items())
    if _INDEX["key"] != key:
        rows = []
        for k, d in DROP.items():
            for a in d["aliases"]:
                na = _norm(a)
                if na:
                    rows.append((k, a, na, _has_hangul(a)))
        _INDEX["key"], _INDEX["rows"] = key, tuple(rows)
    return _INDEX["rows"]


def is_dropped(header: str) -> str:
    """이 머리글이 '받지 않는 것' 인가 — 맞으면 그 까닭의 열쇠를 돌려준다."""
    return (dropped_because(header) or {}).get("key", "")


def dropped_because(header: str) -> dict:
    """왜 버렸는지 **그 낱말까지** 돌려준다 — 사람이 머리글을 고쳐 다시 올릴 수 있게."""
    h = _norm(header)
    if not h:
        return {}
    toks = _tokens(header)
    for key, a, na, hangul in _drop_index():
        if _alias_hits(na, h, toks, hangul):
            return {"key": key, "word": a,
                    "how": "contains" if (hangul or len(na) > SHORT) else "word"}
    return {}


_LATINISH = ("\u0400-\u04ff",     # 키릴
              "\u0370-\u03ff",     # 그리스
              "\u0500-\u052f")     # 키릴 보충


def mixed_script(h) -> bool:
    """라틴 글자와 **겉보기가 같은 다른 글자**가 한 이름에 섞였는가.

    NFKC 로도 키릴 'а' 는 라틴 'a' 가 되지 않는다. 'pаssword' 로 우리 검사를 비켜 갈 수 있다.
    남의 파일이므로 거절하지는 않고 자동으로 맞추지만 않는다 — 정상 파일일 수도 있다.
    """
    import re as _re
    t = str(h or "")
    if not _re.search(r"[A-Za-z]", t):
        return False
    return bool(_re.search("[" + "".join(_LATINISH) + "]", t))


_CTRL = chr(9) + chr(10) + chr(13) + chr(11) + chr(12)


def safe_header(h, keep: int = 3) -> str:
    """밖으로 내보낼 수 있는 꼴의 머리글.

    ① 제어문자를 걷는다 — 남의 파일 머리글로 로그 한 줄을 꾸며 내지 못하게.
    ② 길면 앞 몇 글자만 남기고 가린다 — 머리글 자리에 값이 들어와 있는 파일이 있다
       ('password=P@ssw0rd'). 가린 뒤에도 몇 번째 열인지로 사람은 알아본다.
    """
    # 공백으로 바꾸는 일이 걸러내는 일보다 **먼저**다 — 뒤집히면 개행이 사라져
    # '호스트명<개행>조작' 이 '호스트명조작' 으로 붙고, 사람이 보는 이름이 원본과 달라진다
    t = "".join(" " if ch in _CTRL else ch for ch in str(h or ""))
    t = "".join(ch for ch in t if ch == " " or ch.isprintable())
    t = " ".join(t.split())
    return t if len(t) <= keep else t[:keep] + "***"


_ZERO_WIDTH = "​‌‍﻿"


def _norm_text(t: str) -> str:
    import unicodedata
    t = unicodedata.normalize("NFKC", t)
    t = "".join(ch for ch in t if ch not in _ZERO_WIDTH)
    return "".join(ch for ch in t.casefold() if ch.isalnum())


def _norm(s) -> str:
    """머리글 비교용 — 공백·기호·대소문자를 지운다('관리 IP' 와 'IP주소' 를 같은 자리에서 본다).

    전각(ＰＷ)·폭 없는 공백으로 검사를 비켜 가지 못하게 NFKC 로 먼저 고르고 casefold 한다.

    **바깥에서 온 글자는 캐시하지 않는다.** 머리글이 그 자체로 비밀일 수 있어서다
    ('password=P@ssw0rd' 같은 머리글이 실제로 있어 가려서 내보내기로 했다). 그것을 프로세스가
    사는 내내 들고 있는 것은 그 결정과 어긋난다(GPT 지적). 어차피 머리글당 한 번씩만 부른다.
    """
    return _norm_text(str(s or ""))

def looks_like_secret(value) -> str:
    """이 **값**이 자격 정보로 보이는가 — 보이면 그 까닭의 이름을 돌려준다.

    파일에서 들어오는 값만 검사하고 사람이 화면에서 직접 적는 값은 아무 검사도 지나지 않았다
    (GPT 11차 상). 같은 검사를 지나게 한다.

    할 수 있는 약속은 여기까지다 — **자격 정보임을 알아볼 수 있는 표기는 막는다. 뜻 표시 없이
    일반 글자 칸에 적힌 비밀값까지 완전히 판별하는 것은 보장하지 않는다.** 'Admin1234' 가
    비밀번호인지 장비 이름인지 문자열만 보고 정할 방법이 없다. 지킬 수 없는 약속은 적지 않는다.
    """
    from . import asset_import
    return asset_import._SECRET_IN_CELL.search(value) or ""


MAX_VALUE = 4000          # 값 하나 (파일 쪽 MAX_CELL 과 같은 선)
MAX_VALUES = 400          # 한 번에 보는 항목 수


def _sane(values) -> dict:
    """검사에 넣기 **전에** 크기를 자른다.

    정규식 검사 자체가 들어오는 문이 되면 안 된다. 파일 쪽은 칸 4000자 상한이 있었지만,
    사람이 화면에서 보내는 JSON 에는 아무 상한도 없었다(GPT 12차).
    """
    if not isinstance(values, dict):
        return {}
    out = {}
    for k, v in list(values.items())[:MAX_VALUES]:
        out[str(k)[:80]] = v[:MAX_VALUE] if isinstance(v, str) else v
    return out


def check(values: dict, asset_type: str = "", extra=None, levels=None) -> dict:
    """빈 필수 항목을 **왜 필요한지와 함께** 돌려준다.

    저장을 막지는 않는다 — 막으면 사람들이 아무 값이나 채워 넣는다. 대신 '미완성' 이라고
    말하고, 그 항목이 없을 때 장애 때 무엇을 못 하는지 그대로 보여 준다.
    """
    values = _sane(values)

    def _filled(fid) -> bool:
        """우리 말로 **읽힌** 값이 있는가.

        `<항목>_raw`(파일에 있었지만 우리가 못 알아본 글자)는 채워진 것으로 세지 않는다.
        세면 '실서비스쯤?' 같은 값으로 운영 환경이 정해진 자산을 '완성' 이라 부르게 된다
        (GPT 10차 상 등급). 버리지는 않고 '확인 필요' 로만 말한다.
        """
        v = values.get(fid)
        return not (v is None or (isinstance(v, str) and not v.strip()))

    def _raw_only(fid) -> bool:
        r = values.get(str(fid) + "_raw")
        return (not _filled(fid)) and not (r is None or (isinstance(r, str) and not r.strip()))

    fs = fields(asset_type, extra, levels)
    missing, weak, groups, unread, tainted = [], [], {}, [], []
    for f in fs:
        # 기준에서 격리한 항목에는 **사람이 직접 적는 것도** 받지 않는다.
        # 자동 채움에서만 빼면 반쪽이다 — 화면으로 넣으면 그대로 들어간다(GPT 12차 조건).
        v = values.get(f["id"])
        if f.get("quarantined") and not (v is None or (isinstance(v, str) and not v.strip())):
            tainted.append({"id": f["id"], "label": f["label"], "reason": "quarantined_field",
                            "why": "이 항목은 우리 보안 기준이 바뀌면서 쓰지 않기로 한 것입니다 —"
                                   " 값을 넣을 수 없습니다. 관리자에게 확인해 주십시오"})
            continue
        # 사람이 적었든 파일에서 왔든, 자격 정보로 보이는 값은 받지 않는다
        hit = looks_like_secret(v)
        if hit:
            tainted.append({"id": f["id"], "label": f["label"], "reason": hit,
                            "why": "이 값이 자격 정보로 해석될 수 있어 받지 않습니다 —"
                                   " 비밀번호·키는 금고에 두고, 여기에는 적지 마십시오"})
        if _raw_only(f["id"]):
            raw = str(values.get(f["id"] + "_raw") or "")
            # 못 알아본 값을 되돌려 주는 것이 또 하나의 출구가 될 수 있다 —
            # 자격 정보로 보이면 원문을 넣지 않고 까닭만 말한다(GPT 11차)
            bad = looks_like_secret(raw)
            unread.append({"id": f["id"], "label": f["label"], "group": f["group"],
                           "raw": "" if bad else raw[:60],
                           "reason": "sensitive_value_dropped" if bad else "",
                           "why": ("이 자리에 들어온 값이 자격 정보로 보여 보여 드리지 않습니다"
                                   if bad else
                                   "이 자리에 들어온 값을 우리 말로 알아보지 못했습니다 —"
                                   " 무엇인지 골라 주셔야 채워집니다")})
        if _filled(f["id"]):
            continue
        row = {"id": f["id"], "label": f["label"], "why": f["why"], "group": f["group"]}
        if f["level"] == "required":
            missing.append(row)
        elif f["level"] == "conditional":
            # 묶음째로 본다 — '하나는 있어야 한다' 이므로 낱개로 나무라지 않는다
            groups.setdefault(f.get("one_of") or f["id"], []).append(row)
        else:
            weak.append(row)

    # 묶음 안에 **하나라도** 채워진 것이 있으면 그 묶음은 넘어간다
    for key, rows in groups.items():
        g = ONE_OF.get(key)
        member_ids = (g or {}).get("fields") or [r["id"] for r in rows]
        here = [i for i in member_ids if any(f["id"] == i for f in fs)]
        if any(_filled(i) for i in here):
            continue
        if g:
            labels = [f["label"] for f in fs if f["id"] in here]
            missing.append({"id": "one_of:" + key, "label": g["label"],
                            "why": g["why"] + " — " + " 또는 ".join(labels) + " 중 하나는 있어야 합니다",
                            "group": rows[0]["group"], "one_of": here})
        else:
            missing.extend(rows)

    typed = bool(asset_type)
    return {"complete": not missing and not unread and not tainted,
            "missing": missing, "advised_missing": weak, "unread": unread,
            "tainted": tainted,
            "scope": "type" if typed else "common", "asset_type": asset_type or None,
            "type_requirements_checked": typed,
            # 기준이 바뀌어 필수가 늘어도 이미 등록된 자산을 깨뜨리지 않는다 —
            # 막는 대신 '확인 필요' 로만 표시한다(GPT 교차 판단)
            # 못 알아본 값이 하나라도 있으면 '확인 필요' 다 — 뜻을 모르는 값으로 완성을 선언하지 않는다
            "state": ("complete" if not missing and not unread and not tainted
                      else "needs_review" if (unread or tainted or values) else "incomplete"),
            "note": ("필수가 비어도 저장은 됩니다 — 다만 [미완성] 으로 표시합니다."
                     if typed else
                     "공통 항목만 검사했습니다 — 유형을 고르면 유형별 필수까지 봅니다.")}


# ── 남이 준 표의 머리글을 우리 항목에 맞춘다 ──────────────────────────────────
# 템플릿을 강요하지 않겠다면, 아무 이름으로 와도 우리 항목을 찾아 줘야 한다.
# 다만 **확신을 지어내지 않는다** — 확실 / 추정 / 모름을 그대로 말하고,
# 추정과 모름은 사람이 확인하게 한다.
SURE, GUESS, NONE = "확실", "추정", "모름"

_IP = __import__("re").compile(r"^\s*\d{1,3}(\.\d{1,3}){3}\s*$")
_DATE = __import__("re").compile(r"^\s*\d{4}[-./]\d{1,2}[-./]\d{1,2}")


def _shape(values) -> str:
    """값 모양 — 머리글이 낯설 때 여기서 한 번 더 넘겨짚는다."""
    vals = [str(v).strip() for v in (values or []) if str(v or "").strip()]
    if not vals:
        return ""
    if sum(1 for v in vals if _IP.match(v)) >= max(1, len(vals) * 0.6):
        return "ip"
    if sum(1 for v in vals if _DATE.match(v)) >= max(1, len(vals) * 0.6):
        return "date"
    return ""


def map_headers(headers, asset_type: str = "", samples=None, extra=None, levels=None) -> dict:
    """머리글 목록 → 우리 항목. 확신도와 버린 열, 못 맞춘 열을 함께 돌려준다.

    headers: ['호스트명','IP주소','비밀번호', ...]
    samples: 열마다의 값 몇 개(선택) — 머리글로 못 맞췄을 때 값 모양으로 한 번 더 본다.

    이름이 꼭 맞는 것을 **먼저 전부** 잡고, 품고 있는지는 그다음에 본다.
    한 번에 훑으면 'NO' 같은 짧은 머리글이 'node' 에 걸려 진짜 'Hostname' 의 자리를 뺏는다.
    """
    fs = fields(asset_type, extra, levels)
    # 한 이름에 후보가 여럿일 수 있다 — 먼저 들어온 쪽이 이기게 두면 판이 바뀔 때
    # 같은 파일이 다른 항목으로 들어간다(GPT 10차 중상). 후보를 모아 두고 겹치면 손을 뗀다.
    cand = {}
    for f in fs:
        # 현장이 만든 자유 서술 항목은 **파일에서 자동으로 채우지 않는다** —
        # 그 칸에 들어온 글자가 비밀번호인지 판별할 방법이 없다(GPT 10차 상).
        if f.get("custom") and not f.get("from_file"):
            continue
        for key in [f["label"]] + list(f.get("aliases") or []):
            k = _norm(key)
            if k:
                cand.setdefault(k, [])
                if f["id"] not in cand[k]:
                    cand[k].append(f["id"])
    by_norm = {k: v[0] for k, v in cand.items() if len(v) == 1}
    ambiguous = {k: v for k, v in cand.items() if len(v) > 1}

    cols = []
    for i, h in enumerate(headers or []):
        # 제어문자를 걷어서 담는다(로그·화면 어디로 가든 한 줄을 꾸며 내지 못하게)
        cols.append({"index": i, "header": safe_header(h, 200), "key": _norm(h),
                     "field": "", "confidence": NONE})

    taken, dropped, unknown, unsure = {}, {}, [], []
    by_label = {f["id"]: f["label"] for f in fs}

    # ① 받지 않는 것부터 걷어낸다
    for c in cols:
        d = is_dropped(c["header"])
        if d:
            # 버린 열의 머리글은 **가린 꼴로만** 내보낸다 — 그 자리에 값이 들어와 있을 수 있다
            c.update(dropped=d, why=DROP[d]["why"], header=safe_header(c["header"]),
                     category=d)
            dropped[str(c["index"])] = d

    # ② 이름이 꼭 맞는 것 — 다만 뜻이 겹치거나 글자가 수상하면 손을 뗀다
    for c in cols:
        if c.get("dropped") or not c["key"]:
            continue
        if mixed_script(c["header"]):
            c.update(field="", confidence=NONE, ambiguous=[], suspicious=True,
                     why="이 이름에 겉보기가 같은 다른 문자가 섞여 있습니다"
                         "(키릴 'а' 처럼) — 우리 검사를 비켜 가려는 것일 수 있어"
                         " 자동으로 맞추지 않습니다. 확인해 주십시오")
            unsure.append(c["index"])
            continue
        if c["key"] in ambiguous:
            ids = ambiguous[c["key"]]
            c.update(field="", confidence=NONE, ambiguous=ids,
                     why="이 이름이 " + " · ".join(by_label.get(i, i) for i in ids)
                         + " 중 무엇인지 우리가 정할 수 없습니다 — 골라 주십시오")
            unsure.append(c["index"])
            continue
        fid = by_norm.get(c["key"])
        if fid and fid not in taken:
            taken[fid] = c["header"]
            c.update(field=fid, confidence=SURE)

    # ③ 남은 것만 '품고 있는지' — 양쪽 다 세 글자 이상일 때만, 긴 쪽을 먼저
    for c in cols:
        if c.get("dropped") or c["field"] or c.get("ambiguous") or len(c["key"]) < 3:
            continue
        best = ""
        for nk, one in sorted(by_norm.items(), key=lambda kv: -len(kv[0])):
            if len(nk) < 3 or one in taken:
                continue
            if nk in c["key"] or c["key"] in nk:
                best = one
                break
        if best:
            taken[best] = c["header"]
            c.update(field=best, confidence=GUESS)

    # ④ 그래도 없으면 값 모양으로
    if samples:
        for c in cols:
            if c.get("dropped") or c["field"] or c.get("ambiguous"):
                continue
            sh = _shape((samples or {}).get(c["index"]) or (samples or {}).get(str(c["index"])))
            if not sh:
                continue
            for f in fs:
                if f["kind"] == sh and f["id"] not in taken:
                    taken[f["id"]] = c["header"]
                    c.update(field=f["id"], confidence=GUESS)
                    break

    for c in cols:
        if not c["field"] and not c.get("dropped"):
            unknown.append(c["index"])
        c.pop("key", None)

    need = [{"id": f["id"], "label": f["label"], "why": f["why"]}
            for f in fs if f["level"] == "required" and f["id"] not in taken]

    # 조건부 묶음도 같이 본다 — '이 중 하나는' 을 아무것도 못 맞췄으면 그것도 빠진 것이다.
    # check() 만 묶음을 보고 여기서는 안 보면, 로그를 볼 곳이 통째로 없는 표가 조용히 통과한다.
    here = {f["id"] for f in fs}
    by_id = {f["id"]: f for f in fs}
    groups = []
    for key, g in ONE_OF.items():
        # 묶음 소속이면 등급이 '권장' 이어도 대신할 수 있는 것으로 센다 —
        # 원격 콘솔만 적어 온 표를 '접속할 방법이 없다' 고 나무라면 거짓말이 된다.
        # check() 와 같은 기준으로 본다(한쪽만 지키면 지키지 않는 것과 같다).
        member = [i for i in g["fields"] if i in here]
        if not member or any(i in taken for i in member):
            continue
        if not any(by_id[i]["level"] == "conditional" for i in member):
            continue                       # 묶음이 이 유형에서는 요구되지 않는다
        groups.append({"id": "one_of:" + key, "label": g["label"], "one_of": member,
                       "why": g["why"] + " — " + " 또는 ".join(by_id[i]["label"] for i in member)
                              + " 중 하나는 있어야 합니다"})
    need += groups

    return {"columns": cols, "dropped": dropped, "unknown": unknown, "ambiguous": unsure,
            "matched": dict(taken), "missing_groups": [g["id"] for g in groups],
            "missing_required": need,
            "counts": {"total": len(cols), "sure": sum(1 for c in cols if c["confidence"] == SURE),
                       "guess": sum(1 for c in cols if c["confidence"] == GUESS),
                       "none": sum(1 for c in cols if c["confidence"] == NONE),
                       "dropped": len(dropped)}}
