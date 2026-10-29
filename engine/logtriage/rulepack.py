"""룰팩(.rpk) 빌드·검증·적용 (설계서 08장).

.rpk = zip 스냅샷: manifest.yaml + rules/ + changelog.yaml + signature.ed25519
서명은 Ed25519 공개키 서명만(2026-10-15 마스터 결정 "틈 닫고 새로운 도장 받기") — 개인키는 인터넷망에만, 폐쇄망은 공개키만.
옛 방식(HMAC-SHA256 공유 비밀키, signature.sig) 룰팩은 만들지도 받지도 않는다 — 첫 공개키 등록 전에도 거부.
이미 적용돼 있는 rules/·errorcodes/·manuals/·rules-local/·rules-learned/(지금까지 반영·학습한 지식)는 이 결정과 무관하게 그대로 쓴다.
적용은 원자적: 검증 통과 시에만 rules/ 백업 후 교체, 실패 시 자동 롤백.
"""
from __future__ import annotations

import hashlib
import shutil
import zipfile
import json
import tempfile
import uuid
import os
from datetime import datetime
from pathlib import Path

import yaml

SIG_FILE = "signature.sig"          # 옛 방식(HMAC 공유 비밀키) 서명 파일 이름 — 2026-10-15 부터 이 파일이 든 룰팩은 거부
SIG_ED = "signature.ed25519"        # 새 방식(2026-10-13, GPT P0-03): Ed25519 — 개인키는 인터넷망에만, 폐쇄망은 공개키만
MANIFEST = "manifest.yaml"
TRUST_FILE = ("conf", "rulepack_trust.pub")   # 폐쇄망이 믿는 서명 공개키(처음 적용할 때 등록, 그 뒤로는 이 키만)
POLICY_FILE = ("conf", "rulepack_policy.json")  # 한 번 공개키 서명으로 넘어가면 기록 — trust 파일이 지워져도 옛 HMAC 으로 돌아가지 않는다


def _digest(zf: zipfile.ZipFile) -> str:
    """서명 대상: 서명 파일을 제외한 전체 엔트리의 SHA256 (이름순)."""
    h = hashlib.sha256()
    for name in sorted(n for n in zf.namelist() if n not in (SIG_FILE, SIG_ED)):
        h.update(name.encode())
        h.update(zf.read(name))
    return h.hexdigest()


# ── Ed25519 ─────────────────────────────────────────────────
def load_signing_key(path: Path, create: bool = False):
    """인터넷망 서명 개인키(PEM). 없으면 create 일 때만 만든다 — 만든 뒤 공개키를 폐쇄망에 한 번 등록해야 한다."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = Path(path)
    if path.exists():
        k = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(k, Ed25519PrivateKey):
            raise ValueError("서명 키가 Ed25519 가 아닙니다")
        return k
    if not create:
        return None
    k = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".new")
    tmp.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)
    return k


def public_bytes(priv) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _load_pub(key: bytes):
    """키 파일 내용이 Ed25519 공개키(PEM 또는 32바이트)면 공개키 객체, 아니면 None(옛 HMAC 키)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        if key.lstrip().startswith(b"-----BEGIN PUBLIC KEY-----"):
            k = serialization.load_pem_public_key(key)
            return k if isinstance(k, Ed25519PublicKey) else None
    except Exception:
        return None
    return None


def fingerprint(pub_pem: bytes) -> str:
    """공개키 지문(SHA-256 앞 32자 = 128비트, 4자씩) — 사람이 두 곳에서 눈으로 맞춰 본다."""
    from cryptography.hazmat.primitives import serialization
    k = _load_pub(pub_pem)
    raw = k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) if k else pub_pem
    h = hashlib.sha256(raw).hexdigest()[:32].upper()
    return "-".join(h[i:i + 4] for i in range(0, 32, 4))


def build(rules_dir: Path, out: Path, key: bytes | None, version: str | None = None,
          changelog: str = "", codes_dir: Path | None = None,
          manuals_dir: Path | None = None, signer=None, link_hosts: list | None = None) -> Path:
    if signer is None:   # 옛 방식(HMAC) 룰팩은 더 만들지 않는다(2026-10-15) — key 인자는 호출 호환용으로만 남김
        raise ValueError("서명 개인키(Ed25519)가 필요합니다 — 옛 방식(HMAC) 룰팩은 만들지 않습니다(인터넷망 conf/rulepack_signing.pem)")
    version = version or datetime.now().strftime("%Y.%m.%d")
    rule_files = sorted(rules_dir.rglob("*.yaml"))
    if not rule_files:
        raise FileNotFoundError(f"룰 없음: {rules_dir}")
    code_files = sorted(codes_dir.rglob("*.yaml")) if codes_dir and codes_dir.exists() else []
    manual_files = sorted(manuals_dir.rglob("*.yaml")) if manuals_dir and manuals_dir.exists() else []
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in rule_files:
            zf.write(f, f"rules/{f.relative_to(rules_dir).as_posix()}")
        for f in code_files:
            zf.write(f, f"errorcodes/{f.relative_to(codes_dir).as_posix()}")
        for f in manual_files:
            zf.write(f, f"manuals/{f.relative_to(manuals_dir).as_posix()}")
        zf.writestr("changelog.yaml", changelog or f"version: {version}\nchanges: []\n")
        zf.writestr(MANIFEST, yaml.safe_dump({
            "version": version,
            "created": datetime.now().isoformat(timespec="seconds"),
            "rule_count": len(rule_files),
            "engine_min": "0.1.0",
            **({"link_hosts": __import__("logtriage.links", fromlist=["validate_hosts"]).validate_hosts(link_hosts)} if link_hosts else {}),
        }, allow_unicode=True))
    # 서명은 나머지 엔트리가 확정된 뒤 추가 — signer(Ed25519 개인키)가 있으면 새 방식만
    with zipfile.ZipFile(out, "a", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(SIG_ED, signer.sign(_digest(zf).encode()).hex())
    return out


def verify(rpk: Path, key: bytes) -> dict:
    with zipfile.ZipFile(rpk) as zf:
        names = zf.namelist()
        from pathlib import PurePosixPath
        if len(names) != len(set(names)) or sum(i.file_size for i in zf.infolist()) > 256*1024*1024:
            raise ValueError('룰팩 중복 파일 또는 해제 크기 초과')
        for n in names:
            p = PurePosixPath(n)
            if p.is_absolute() or '..' in p.parts or '\\' in n or ':' in n:
                raise ValueError('룰팩 경로 오류')
        if MANIFEST not in names or (SIG_FILE not in names and SIG_ED not in names):
            raise ValueError("룰팩 형식 오류: manifest/signature 누락")
        if SIG_FILE in names:   # 옛 도장(HMAC) — 공개키 등록 전이든 후든 받지 않는다(2026-10-15 마스터 결정: 틈 닫기)
            raise ValueError("옛 방식(HMAC) 룰팩은 받지 않습니다 — 인터넷망 [룰팩 만들기]에서 공개키 서명(Ed25519) 룰팩으로 다시 만들어 오십시오. "
                             "지금 적용돼 있는 룰·코드·학습 룰은 그대로입니다")
        pub = _load_pub(key)
        if pub is None:
            raise ValueError("서명 공개키(rulepack-signing.pub, Ed25519)가 아닙니다 — 옛 배포 키(.key)로는 검증하지 않습니다")
        try:
            pub.verify(bytes.fromhex(zf.read(SIG_ED).decode().strip()), _digest(zf).encode())
        except Exception:
            raise ValueError("서명 검증 실패 — 위·변조 또는 다른 서명 키") from None
        m = yaml.safe_load(zf.read(MANIFEST))
        if isinstance(m, dict):
            m["_signature"] = "ed25519"
        return m


def _swap_in(zf: zipfile.ZipFile, prefix: str, dest_dir: Path):
    """검증된 zip 의 prefix/ 항목으로 dest_dir 을 원자적 교체 (실패 시 롤백)."""
    backup = dest_dir.with_name(dest_dir.name + ".bak")
    if backup.exists():
        shutil.rmtree(backup)
    if dest_dir.exists():
        dest_dir.rename(backup)
    try:
        dest_dir.mkdir(parents=True)
        for name in zf.namelist():
            if name.startswith(prefix + "/") and name.endswith(".yaml"):
                dest = dest_dir / Path(name).relative_to(prefix)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(zf.read(name))
    except Exception:
        shutil.rmtree(dest_dir, ignore_errors=True)  # 롤백
        if backup.exists():
            backup.rename(dest_dir)
        raise


def _journal(path, value):
    tmp = path.with_suffix('.tmp')
    with tmp.open('w', encoding='utf-8') as stream:
        json.dump(value, stream)
        stream.flush(); os.fsync(stream.fileno())
    tmp.replace(path)


def recover(base: Path):
    """Recover all three trees together after process interruption."""
    root=Path(base)/'.rpk-transactions'
    for journal in sorted(root.glob('*/transaction.json')):
        m=json.loads(journal.read_text(encoding='utf-8'))
        if m['state']!='applying':continue
        for name,had in m['previous'].items():
            if name not in ('rules','errorcodes','manuals'):raise ValueError('복구 경로 오류')
            target=Path(base)/name
            if target.is_symlink():raise ValueError('복구 링크 거부')
            if target.exists():shutil.rmtree(target)
            if had:shutil.copytree(journal.parent/'previous'/name,target)
        m['state']='rolled_back';_journal(journal,m)

class TrustNeeded(ValueError):
    """처음 받는 서명 키 — 인터넷망 [룰팩 만들기] 화면에 나온 지문을 사람이 입력해야 등록·적용한다."""
    def __init__(self, fp: str):
        super().__init__(f"처음 보는 서명 키입니다(지문 {fp}) — 인터넷망 룰팩 만들기 화면에 나온 지문을 입력해야 등록·적용합니다")
        self.fp = fp


def _vkey(v) -> tuple:
    """판 비교 — 'YYYY.MM.DD.HHMM' 같은 숫자 마디를 모두 비교(앞 세 마디만 보면 같은 날 두 판을 못 가린다)."""
    import re as _re
    return tuple(int(x) for x in _re.findall(r"\d+", str(v or "")))


def _fp_norm(s: str) -> str:
    import re as _re
    return _re.sub(r"[^0-9A-F]", "", str(s or "").upper())


def _refresh_manifest(base: Path) -> None:
    """정당한 지식 교체(룰팩 적용) 뒤 지식 매니페스트(파일 해시·룰/코드 수)를 새로 쓴다 — 안 쓰면 다음 분석부터
    '지식 파일이 설치 기록과 다름' 거짓 경보가 난다(2026-10-16 아이디어 10). 실패해도 적용은 이미 끝났다 — 경보로 드러난다."""
    try:
        from . import knowledge_quality as KQ
        from .codes import load_codes
        from .rules import load_rules
        KQ.write_manifest(base, {"rules": len({r.id for r in load_rules(base / "rules", None)}),
                                 "codes": len(load_codes(base / "errorcodes"))})
    except Exception:   # noqa: BLE001 — 매니페스트는 경보용 기록일 뿐
        pass


def apply(rpk: Path, rules_dir: Path, key: bytes,
          codes_dir: Path | None = None,
          manuals_dir: Path | None = None, confirm_fp: str | None = None) -> dict:
    manifest = verify(rpk, key)
    if not isinstance(manifest,dict) or not manifest.get('version'):raise ValueError('manifest 버전 필요')
    # 서명 키 고정(GPT P0-03): 공개키를 한 번 등록하면 그 뒤로는 그 키로 서명한 룰팩만 — 옛 HMAC 룰팩도 받지 않는다
    trust = Path(rules_dir).resolve().parent.joinpath(*TRUST_FILE)
    policy = Path(rules_dir).resolve().parent.joinpath(*POLICY_FILE)
    policy2 = Path(rules_dir).resolve().parent / '.rpk-transactions' / 'policy.json'   # 같은 기록 한 벌 더(한 파일만 지워서는 되돌아가지 않게)
    if manifest.get('_signature') != 'ed25519':   # verify 가 이미 막지만 적용 단계에서도 한 번 더(방어 두 겹)
        raise ValueError('공개키 서명(Ed25519) 룰팩만 받습니다')
    if True:   # (예전엔 HMAC 갈래가 따로 있었다 — 2026-10-15 제거)
        fp = fingerprint(key)
        if trust.exists():
            if fingerprint(trust.read_bytes()) != fp:
                raise ValueError(f'등록된 서명 키와 다릅니다 — 등록 {fingerprint(trust.read_bytes())} / 이번 {fp}')
        else:
            # 같은 매체로 온 공개키는 룰팩과 함께 바꿔치기될 수 있다 — 원본(인터넷망) 화면의 지문을 사람이 옮겨 적어야 믿는다
            if _fp_norm(confirm_fp) != _fp_norm(fp):
                raise TrustNeeded(fp)
            manifest['_trust_new'] = True
        manifest['_signer_fp'] = fp
        # (판 검사는 서명 키 검사 뒤 — 믿지 않는 키의 룰팩이면 키 문제를 먼저 알린다)
        # 되돌리기 차단(실증 ⑤): 공개키 서명 룰팩은 마지막으로 적용한 판보다 옛 판을 받지 않는다(같은 판 재적용은 허용)
        last = ''
        for pol in (policy, policy2):
            try:
                last = max(last, json.loads(pol.read_text(encoding='utf-8')).get('last_version') or '', key=_vkey)
            except (OSError, ValueError):
                pass
        if last and _vkey(manifest['version']) < _vkey(last):
            raise ValueError(f"옛 판 룰팩입니다(이번 {manifest['version']} < 마지막 적용 {last}) — 되돌리기는 받지 않습니다")
        with zipfile.ZipFile(rpk) as _zf:
            manifest['_digest'] = _digest(_zf)
        if last and _vkey(manifest['version']) == _vkey(last):
            # 두 기록 중 마지막 판과 같은 판의 해시를 모두 본다 — 서로 다르면 어느 하나를 고르지 않고 멈춘다(GPT 9차)
            dgs = set()
            for pol in (policy, policy2):
                try:
                    rec = json.loads(pol.read_text(encoding='utf-8'))
                except (OSError, ValueError):
                    continue
                if rec.get('last_digest') and _vkey(rec.get('last_version') or '') == _vkey(last):
                    dgs.add(rec['last_digest'])
            if len(dgs) > 1:
                raise ValueError(f"룰팩 적용 기록 두 곳(conf/rulepack_policy.json · .rpk-transactions/policy.json)의 {last} 내용 해시가 서로 다릅니다 — 관리자가 확인하십시오")
            if dgs and manifest['_digest'] not in dgs:
                raise ValueError(f"같은 판({manifest['version']})인데 내용이 다른 룰팩입니다 — 새 판으로 다시 만들어 오십시오")
    from . import __version__
    def version(v):return tuple(int(x) for x in __import__('re').findall(r'\d+',str(v))[:3])
    if version(manifest.get('engine_min','0'))>version(__version__):raise ValueError('엔진 버전 부족')
    from .links import validate_hosts
    link_hosts=validate_hosts(manifest.get('link_hosts'))   # 3차 아이디어 4: 서명 범위 안의 링크 도메인 — 형식이 틀리면 룰팩 전체를 받지 않는다
    base=Path(rules_dir).resolve().parent
    targets={'rules':Path(rules_dir)}
    if codes_dir:targets['errorcodes']=Path(codes_dir)
    if manuals_dir:targets['manuals']=Path(manuals_dir)
    if any(p.resolve()!=base/n or p.is_symlink() for n,p in targets.items()):raise ValueError('룰팩 대상은 동일 설치 폴더의 표준 경로여야 합니다')
    from .automation import InstanceLock
    lock=InstanceLock(base/'.rpk-apply.lock');lock.acquire()
    try:
        recover(base)
        with tempfile.TemporaryDirectory(prefix='.rpk-stage-',dir=base) as td:
            stage=Path(td)
            with zipfile.ZipFile(rpk) as z:
                included={n for n in targets if any(x.startswith(n+'/') and x.endswith('.yaml') for x in z.namelist())}
                if 'rules' not in included:raise ValueError('룰이 없는 패키지')
                for name in included:
                    for entry in z.namelist():
                        if entry.startswith(name+'/') and entry.endswith('.yaml'):
                            raw=z.read(entry);yaml.safe_load(raw)
                            dst=stage/entry;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw)
                from .rules import _load_file
                loaded=[r for f in (stage/'rules').rglob('*.yaml') for r in _load_file(f,'rulepack')]
                if not loaded or len({r.id for r in loaded})!=len(loaded):raise ValueError('룰 ID 중복 또는 빈 규칙')
                if 'errorcodes' in included:
                    from .codes import load_codes
                    load_codes(stage/'errorcodes')
                for path in (stage/'manuals').glob('*_procedures.yaml'):
                    doc=yaml.safe_load(path.read_text(encoding='utf-8'))
                    if not isinstance(doc,dict) or not isinstance(doc.get('procedures'),list):
                        raise ValueError('매뉴얼 절차 형식 오류')
                    for procedure in doc['procedures']:
                        if not isinstance(procedure,dict) or not procedure.get('id') or not isinstance(procedure.get('stages'),list):
                            raise ValueError('매뉴얼 절차 ID/stages 오류')
                for path in (stage/'manuals').glob('*_proclinks.yaml'):   # 절차 연결 파일(아이디어 3) — 형식이 틀리면 통째 거부
                    doc=yaml.safe_load(path.read_text(encoding='utf-8'))
                    if not isinstance(doc,dict) or not isinstance(doc.get('links'),list) or not all(isinstance(x,dict) and x.get('procedure') and isinstance(x.get('match'),list) for x in doc['links']):
                        raise ValueError('절차 연결 형식 오류')
            tx=base/'.rpk-transactions'/uuid.uuid4().hex;tx.mkdir(parents=True)
            previous={n:targets[n].exists() for n in included}
            for n,had in previous.items():
                if had:shutil.copytree(targets[n],tx/'previous'/n)
            journal=tx/'transaction.json';m={'state':'applying','previous':previous,'version':manifest['version']}
            _journal(journal,m)
            try:
                for n in sorted(included):
                    if targets[n].exists():shutil.rmtree(targets[n])
                    (stage/n).rename(targets[n])
                m['state']='committed';_journal(journal,m)
                try:   # 9차 ⑦: 지식 세대 기록 갱신(포함되지 않은 폴더도 같이 지문) — 안 하면 다음 기동이 '한 폴더만 바뀜'으로 거부한다
                    from .knowledge_gen import write_gen
                    write_gen(base, 'rulepack ' + str(manifest.get('version', '')))
                except OSError:
                    pass
                if manifest.get('_trust_new'):   # 적용까지 끝난 뒤에 등록(검증·적용 실패 때 남지 않게)
                    trust.parent.mkdir(parents=True,exist_ok=True)
                    tmp=trust.with_suffix('.pub.new');tmp.write_bytes(key);os.replace(tmp,trust)
                if manifest.get('_signature')=='ed25519':   # 전환 기록 + 마지막 적용 판(두 곳)
                    prev={}
                    try:prev=json.loads(policy.read_text(encoding='utf-8'))
                    except (OSError,ValueError):pass
                    rec=json.dumps({'mode':'ed25519','since':prev.get('since') or datetime.now().isoformat(timespec='seconds'),
                                    'signer_fp':manifest.get('_signer_fp'),'last_version':str(manifest['version']),
                                    'last_digest':manifest.get('_digest',''),'link_hosts':link_hosts},ensure_ascii=False)
                    for pol in (policy,policy2):
                        pol.parent.mkdir(parents=True,exist_ok=True)
                        tmp=pol.with_suffix('.json.new');tmp.write_text(rec,encoding='utf-8');os.replace(tmp,pol)
            except Exception:
                recover(base);raise
            prune(base)
            _refresh_manifest(base)
        return manifest
    finally:lock.release()


def prune(base: Path, keep: int = 3):
    """Finished transactions keep a full copy of rules/errorcodes/manuals; retain only the newest few (r2)."""
    root=Path(base)/'.rpk-transactions'
    done=[]
    for journal in root.glob('*/transaction.json'):
        try:
            if json.loads(journal.read_text(encoding='utf-8')).get('state')!='applying':done.append(journal)
        except (OSError,ValueError):continue
    done.sort(key=lambda j:j.stat().st_mtime)
    for journal in done[:max(0,len(done)-keep)]:shutil.rmtree(journal.parent,ignore_errors=True)
