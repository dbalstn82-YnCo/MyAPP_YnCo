"""Verified snapshots and offline transactional restore. No shell commands."""
import hashlib,json,os,shutil,sqlite3,tempfile,time,uuid,zipfile
from pathlib import Path,PurePosixPath
from datetime import datetime

ROOTS=('data','incidents','uploads','reports','rules','rules-local','errorcodes','manuals','report-template')
FILES=('incidents.json','settings.json','server.conf','automation-config.json')
DB_COLUMNS={'incidents':('id','analyzed_at','name','layer','verdict','critical','data'),
            'events':('id','incident_id','ts','host','layer','product','severity','code','message','raw_ref')}
EXTERNAL_DUMP='data/automation-backup/analysis-database.jsonl'
TRANSIENT=('uploads/automation/',)   # temporary copies made by the log watcher


def export_database(storage, dest):
    """Portable app-table snapshot, including PostgreSQL, without credentials in output."""
    dest.parent.mkdir(parents=True,exist_ok=True)
    counts={}
    with storage._conn() as connection, dest.open('w',encoding='utf-8') as out:
        cursor=connection.cursor()
        if storage.kind=='postgresql':
            cursor.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        else:
            cursor.execute('BEGIN')
        out.write(json.dumps({'schema':1,'kind':storage.kind})+'\n')
        for table,columns in DB_COLUMNS.items():
            reader=connection.cursor(name='lt_backup_'+table) if storage.kind=='postgresql' else connection.cursor()
            reader.execute('SELECT '+','.join(columns)+' FROM '+table+' ORDER BY id')
            count=0
            while True:
                rows=reader.fetchmany(1000)
                if not rows:break
                for row in rows:
                    out.write(json.dumps({'table':table,'values':list(row)},ensure_ascii=False)+'\n');count+=1
            reader.close()
            counts[table]=count
    return {'kind':storage.kind,'counts':counts,'path':EXTERNAL_DUMP}


def import_database(storage, source):
    """One DB transaction; failure rolls back both app tables."""
    with storage._lock,storage._conn() as connection,source.open(encoding='utf-8') as stream:
        header=json.loads(next(stream))
        if header.get('schema')!=1 or header.get('kind')!=storage.kind:raise ValueError('분석 DB 종류 불일치')
        cursor=connection.cursor()
        for table in ('events','incidents'):cursor.execute('DELETE FROM '+table)
        for line in stream:
            row=json.loads(line);table=row['table']
            if table not in DB_COLUMNS or len(row['values'])!=len(DB_COLUMNS[table]):raise ValueError('분석 DB 덤프 형식 오류')
            query='INSERT INTO '+table+'('+','.join(DB_COLUMNS[table])+') VALUES('+','.join('?' for _ in DB_COLUMNS[table])+')'
            cursor.execute(storage._q(query),row['values'])
        if storage.kind=='postgresql':
            cursor.execute("SELECT setval(pg_get_serial_sequence('events','id'), COALESCE(MAX(id),1), COUNT(*)>0) FROM events")
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

OWNER='.owner'

def _alive(pid):
    """그 프로세스가 아직 살아 있나 — 읽기만 한다(Windows 의 os.kill(pid,0) 은 프로세스를 실제로 끝낼 수 있어 쓰지 않는다).
    확인할 수 없으면 살아 있다고 본다(지우지 않는 쪽)."""
    try:pid=int(pid)
    except (TypeError,ValueError):return True
    if pid<=0:return True
    if os.name=='nt':
        import ctypes
        k=ctypes.windll.kernel32
        h=k.OpenProcess(0x1000,False,pid)          # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:return k.GetLastError()!=87     # 87(잘못된 매개변수) = 없는 프로세스, 그 밖(5 권한 등)은 살아 있다고 본다
        try:
            code=ctypes.c_ulong()
            return not k.GetExitCodeProcess(h,ctypes.byref(code)) or code.value==259   # STILL_ACTIVE
        finally:k.CloseHandle(h)
    try:os.kill(pid,0)
    except ProcessLookupError:return False
    except OSError:return True
    return True

def _is_link(d):
    return d.is_symlink() or bool(getattr(d,'is_junction',lambda:False)())

_REPARSE=0x400   # FILE_ATTRIBUTE_REPARSE_POINT — 정션·심볼릭 링크·그 밖의 재분석 지점

def _is_reparse(st):
    return __import__('stat').S_ISLNK(st.st_mode) or bool(getattr(st,'st_file_attributes',0)&_REPARSE)

def _rm_nofollow(root,done=None):
    """링크를 따라가지 않고 지운다(GPT 38차 — 검사 뒤 바꿔치기): 들어가기 전·항목마다 지우기 직전에 lstat 으로 다시 보고,
    재분석 지점이면 그 링크 자체만 떼고 안으로 들어가지 않는다. lstat 과 열기 사이의 아주 짧은 틈은 남는다 —
    그 틈은 '자료 폴더에 쓸 수 있는 사람'만 쓸 수 있어 _shared_writable 로 넓은 쓰기 권한이 있으면 아예 지우지 않는다."""
    root=str(root);done=done if done is not None else [0]   # done[0] = 지운 항목 수(일부만 지웠을 때 감사 기록용)
    st=os.lstat(root)
    if _is_reparse(st):
        try:os.rmdir(root)
        except OSError:os.unlink(root)
        done[0]+=1
        return
    for e in os.scandir(root):
        st=os.lstat(e.path)
        if _is_reparse(st):
            try:os.rmdir(e.path)          # 디렉터리 정션·링크 — 링크만 떨어진다(대상은 그대로)
            except OSError:os.unlink(e.path)
            done[0]+=1
        elif __import__('stat').S_ISDIR(st.st_mode):
            if _one_untrusted(e.path,_me()):raise PermissionError('하위 폴더에 믿지 않는 쓰기 권한: '+e.name[:40])   # GPT 40차
            _rm_nofollow(e.path,done)
        else:
            os.unlink(e.path);done[0]+=1
    os.rmdir(root);done[0]+=1

# GPT 38·39차: 지우는 폴더에 '믿는 주체' 밖의 누가 쓸 수 있으면 지우지 않는다 — 넓은 집단 목록이 아니라 허용 목록으로 본다.
# 믿는 주체 = SYSTEM · Administrators · TrustedInstaller · 지금 이 프로그램을 돌리는 계정 · CREATOR OWNER/OWNER RIGHTS(만든 사람 자리표).
# 그 밖의 모든 SID(로컬·도메인 그룹, 다른 사용자, 앱 컨테이너…)에 쓰기류 허용 ACE 가 있거나, 소유자가 믿는 주체가 아니면 '공유'로 본다.
_TRUSTED_SIDS={'SY','BA','CO','OW','S-1-5-18','S-1-5-32-544','S-1-3-0','S-1-3-4',
               'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'}   # TrustedInstaller
_RIGHTS={'CC':0x1,'DC':0x2,'LC':0x4,'SW':0x8,'RP':0x10,'WP':0x20,'DT':0x40,'LO':0x80,'CR':0x100,'SD':0x10000,'RC':0x20000,'WD':0x40000,
         'WO':0x80000,'GA':0x10000000,'GX':0x20000000,'GW':0x40000000,'GR':0x80000000,'FA':0x1F01FF,'FR':0x120089,'FW':0x120116,'FX':0x1200A0}
_WRITE_BITS=0x2|0x4|0x40|0x10000|0x40000|0x80000|0x10000000|0x40000000   # 파일 추가·하위 폴더 추가·하위 삭제·삭제·권한/소유자 변경·전체/쓰기

def sddl_untrusted_write(sddl,me=None,mask=None,self_only=False):
    """보안 설명자 SDDL 에서 믿는 주체 밖의 쓰기 — 허용 ACE(A·OA·XA·ZA, 상속 전용 포함: 새 하위 폴더에 붙는다) 또는 믿지 않는 소유자.
    모르는 권한 글자·읽을 수 없는 형식은 쓰기로 본다(지우지 않는 쪽)."""
    import re as _re
    trusted=_TRUSTED_SIDS|({me.upper()} if me else set())
    if not sddl or 'D:' not in sddl:return True
    m=_re.search(r'O:([A-Z]{2}|S-[0-9-]+)',sddl)
    if m and m.group(1).upper() not in trusted:return True       # 소유자는 언제든 권한을 바꿀 수 있다
    for typ,_f,rights,_g,_ig,sid in _re.findall(r'\(([A-Z]+);([A-Z]*);([^;]*);([^;]*);([^;]*);([^)]*)\)',sddl):
        if typ not in ('A','OA','XA','ZA') or sid.strip().upper() in trusted:continue
        if self_only and 'IO' in _f:continue          # 상속 전용 ACE 는 그 폴더 자신에는 걸리지 않는다(위 경로 검사용)
        r=rights.strip()
        if r.lower().startswith('0x'):
            try:bits=int(r,16)
            except ValueError:return True
        else:
            if len(r)%2:return True
            bits=0
            for i in range(0,len(r),2):
                if r[i:i+2] not in _RIGHTS:return True
                bits|=_RIGHTS[r[i:i+2]]
        if bits&(_WRITE_BITS if mask is None else mask):return True
    return False

# 위 경로(조상 폴더) 검사용 — 이미 있는 경로 성분을 지우거나 이름을 바꿀 수 있는 권한: 하위 지우기·지우기·권한/소유자 변경·전체
_SWAP_BITS=0x40|0x10000|0x40000|0x80000|0x10000000

def _win():
    import ctypes
    from ctypes import wintypes
    adv=ctypes.windll.advapi32;k32=ctypes.windll.kernel32
    adv.GetNamedSecurityInfoW.argtypes=[wintypes.LPCWSTR,ctypes.c_int,wintypes.DWORD]+[ctypes.POINTER(ctypes.c_void_p)]*5
    adv.GetNamedSecurityInfoW.restype=wintypes.DWORD
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,
                                                                      ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.DWORD)]
    adv.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
    k32.GetCurrentProcess.restype=wintypes.HANDLE
    k32.CloseHandle.argtypes=[wintypes.HANDLE]
    k32.LocalFree.argtypes=[ctypes.c_void_p];k32.LocalFree.restype=ctypes.c_void_p
    return ctypes,wintypes,adv,k32

def _sd_sddl(path):
    """소유자 + DACL 을 SDDL 글자로(읽지 못하면 None)."""
    ctypes,wintypes,adv,k32=_win()
    psd=ctypes.c_void_p()
    if adv.GetNamedSecurityInfoW(str(path),1,1|4,None,None,None,None,ctypes.byref(psd))!=0:return None   # SE_FILE_OBJECT, OWNER|DACL
    try:
        s=ctypes.c_void_p();n=wintypes.DWORD()
        if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(psd,1,1|4,ctypes.byref(s),ctypes.byref(n)):return None
        try:return ctypes.wstring_at(s.value)
        finally:k32.LocalFree(s)
    finally:k32.LocalFree(psd)

def _my_sid():
    """이 프로세스 계정의 SID 글자(못 읽으면 None)."""
    ctypes,wintypes,adv,k32=_win()
    tok=wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),0x8,ctypes.byref(tok)):return None   # TOKEN_QUERY
    try:
        n=wintypes.DWORD()
        adv.GetTokenInformation(tok,1,None,0,ctypes.byref(n))                                   # TokenUser 크기
        buf=ctypes.create_string_buffer(n.value or 1)
        if not adv.GetTokenInformation(tok,1,buf,n,ctypes.byref(n)):return None
        psid=ctypes.cast(buf,ctypes.POINTER(ctypes.c_void_p))[0]                                 # TOKEN_USER.User.Sid
        s=ctypes.c_void_p()
        if not adv.ConvertSidToStringSidW(psid,ctypes.byref(s)):return None
        try:return ctypes.wstring_at(s.value)
        finally:k32.LocalFree(s)
    finally:k32.CloseHandle(tok)

def _posix_untrusted(p,chain=False):
    """리눅스·유닉스: 소유자가 root·나 아님, POSIX 확장 ACL(접근·기본)이 있음, 그룹·다른 사람 쓰기(g+w·o+w) = 공유.
    위 경로(chain)는 쓰기가 있어도 sticky(+t, /tmp 같은)면 남의 항목 이름을 못 바꾸므로 괜찮다."""
    st=os.stat(p)
    if st.st_uid not in (0,os.geteuid()):return True
    for x in ('system.posix_acl_access',)+(() if chain else ('system.posix_acl_default',)):
        try:
            if os.getxattr(p,x):return True      # 최소 ACL 은 xattr 이 없다 — 있으면 확장 ACL
        except (OSError,AttributeError):pass
    if st.st_mode&0o022:return not (chain and st.st_mode&0o1000)
    return False

def _one_untrusted(p,me,chain=False):
    if os.name=='nt':
        sd=_sd_sddl(p)
        if sd is None:return True
        return sddl_untrusted_write(sd,me,_SWAP_BITS,True) if chain else sddl_untrusted_write(sd,me)
    return _posix_untrusted(p,chain)

def _me():
    return _my_sid() if os.name=='nt' else 'posix'

def _shared_writable(*paths):
    """자료 폴더·지울 폴더를 믿는 주체 밖의 누가 쓸 수 있으면 True. 확인하지 못하면 True(지우지 않는 쪽).
    GPT 40차: 그 폴더뿐 아니라 뿌리까지의 위 경로도 — 남이 경로 성분을 지우거나 이름을 바꿔 다른 곳으로 돌릴 수 있으면 공유."""
    try:me=_me()
    except (OSError,AttributeError,ValueError):return True
    if not me:return True
    seen=set()
    for p in paths:
        try:
            p=Path(os.path.abspath(p))
            if _one_untrusted(p,me):return True
            for a in p.parents:
                if a in seen:continue
                seen.add(a)
                if _one_untrusted(a,me,chain=True):return True
        except (OSError,AttributeError,ValueError):return True
    return False

SHARED_MSG='자료 폴더에 이 프로그램 계정·관리자 말고도 쓸 수 있는 사용자·그룹이 있어 지우지 않습니다 — 폴더 권한을 서비스 계정·관리자로 좁히십시오'

def _has_link(d):
    """하위 어디든 링크·정션이 있으면 True — 지우기 직전 재검사(GPT 25차: 따라가서 바깥 파일을 지우는 일이 없게)."""
    for root,dirs,files in os.walk(d,followlinks=False):
        for n in dirs+files:
            if _is_link(Path(root)/n):return True
    return False

def stale_unowned(base):
    """주인 표식이 없는 임시 백업 폴더 — 자동으로 지우지 않는다(이전 판이 시작한 긴 백업일 수 있다). 관리자 확인 대상."""
    return [d for d in Path(base).glob('.backup-*') if d.is_dir() and not _is_link(d) and not (d/OWNER).is_file()]

_TMP_NAME=__import__('re').compile(r'\.backup-[A-Za-z0-9_]{1,40}')
QUIET_SEC=600   # 10분 안에 바뀐 파일이 있으면 아직 쓰는 중일 수 있다 — 관리자도 지우지 못한다

QZ='.backup-QZ_'   # 격리한 폴더 이름 앞머리 — tempfile 이름은 소문자·숫자·밑줄뿐이라 겹치지 않는다
QZ_MARK='.qz'

def _owner_pid(own):
    """주인 표식(.owner = {"pid": n})의 pid. 표식이 JSON 사전이 아니면(손상·위조) ValueError — 부르는 쪽이 '주인 모름'으로 다룬다.
    10-16 실측: 숫자만 든 표식 하나로 관리자 임시 백업 목록 API 가 AttributeError 로 끊기고, 백업 시작 때 정리도 멈췄다."""
    doc=json.loads(own.read_text(encoding='utf-8'))
    if not isinstance(doc,dict):raise ValueError('주인 표식 형식 오류')
    return doc.get('pid')

def _tmp_state(d):
    """in_use = 주인 프로세스가 살아 있음 / orphan = 주인이 끝남(다음 백업 때 자동 정리) / unowned = 주인 표식 없음(관리자 확인)
    quarantined = 관리자가 격리함(10분 뒤 지울 수 있음) / link = 링크·정션"""
    if _is_link(d):return 'link'
    if d.name.startswith(QZ):return 'quarantined'
    own=d/OWNER
    if not own.is_file():return 'unowned'
    try:pid=_owner_pid(own)
    except (OSError,ValueError):return 'unowned'
    return 'in_use' if pid is None or _alive(pid) else 'orphan'

def _tmp_size(d):
    n=c=0;newest=0.0
    for root,dirs,files in os.walk(d,followlinks=False):
        dirs[:]=[x for x in dirs if not _is_link(Path(root)/x)]
        for f in files:
            p=Path(root)/f
            if _is_link(p) or f==QZ_MARK:continue
            try:st=p.stat()
            except OSError:continue
            n+=st.st_size;c+=1;newest=max(newest,st.st_mtime)
    return n,c,newest

def _zip_busy(base):
    for p in (Path(base)/'backups').glob('*.partial'):
        try:
            if time.time()-p.stat().st_mtime<QUIET_SEC:return True
        except OSError:continue
    return False

QREG = 'tmp_quarantine.json'   # 7차 아이디어 5: 격리 기록은 폴더 밖(conf)에 — 폴더와 기록을 함께 바꿔 '격리 10분'을 꾸미지 못하게


def _qreg_path(base):
    return Path(base)/'conf'/QREG


def _qreg(base):
    try:
        d=json.loads(_qreg_path(base).read_text(encoding='utf-8'))
        return d if isinstance(d,dict) else {}
    except (OSError,ValueError):
        return {}


def _qreg_write(base,reg):
    pth=_qreg_path(base);pth.parent.mkdir(parents=True,exist_ok=True)
    tmp=pth.with_suffix('.json.new');tmp.write_text(json.dumps(reg,ensure_ascii=False),encoding='utf-8');os.replace(tmp,pth)


def content_digest(d):
    """폴더 내용 지문 — (상대 경로, 크기, 파일 내용 sha256) 전부의 sha256. 경로·크기·시각만으로는 내용이 바뀐 것을 못 잡는다(GPT 60차).
    링크·정션은 따라가지 않고 '링크'로 적는다(지울 때 어차피 거절)."""
    h=hashlib.sha256()
    root=Path(d)
    for dp,dirs,files in os.walk(root,followlinks=False):
        dirs.sort();files.sort()
        for x in list(dirs):
            if _is_link(Path(dp)/x):h.update(f'L|{(Path(dp)/x).relative_to(root).as_posix()}\n'.encode())
        for f in files:
            fp=Path(dp)/f
            if f==QZ_MARK and Path(dp)==root:continue   # 화면용 표식은 지문에서 뺀다
            rel=fp.relative_to(root).as_posix()
            if _is_link(fp):h.update(f'L|{rel}\n'.encode());continue
            fh=hashlib.sha256()
            with open(fp,'rb') as fo:
                for b in iter(lambda:fo.read(1<<20),b''):fh.update(b)
            h.update(f'F|{rel}|{fp.stat().st_size}|{fh.hexdigest()}\n'.encode())
    return h.hexdigest()


def _qz_since(d):
    try:return float(json.loads((d/QZ_MARK).read_text(encoding='utf-8')).get('at') or 0)
    except (OSError,ValueError,TypeError):return 0.0

def _action(st,newest,qz_at,busy):
    """화면 버튼 — quarantine(격리) / delete(지우기) / None. 서버가 누를 때 다시 모두 확인한다."""
    now=time.time()
    if st=='orphan':return 'delete' if now-newest>=QUIET_SEC else None
    if st=='unowned':return 'quarantine' if now-newest>=QUIET_SEC and not busy else None
    if st=='quarantined':return 'delete' if qz_at and now-qz_at>=QUIET_SEC else None
    return None

def list_backups(base):
    """관리자 화면(아이디어 9): 남은 임시 백업 폴더 — 이름·상태·크기·파일 수·마지막 변경만(내용·경로 없음)."""
    out=[];busy=_zip_busy(base)
    for d in sorted(Path(base).glob('.backup-*')):
        if not _TMP_NAME.fullmatch(d.name):continue
        try:
            st=_tmp_state(d)
            if st!='link' and not d.is_dir():continue
            n,c,newest=(0,0,0.0) if st=='link' else _tmp_size(d)
            try:newest=max(newest,d.lstat().st_mtime if st!='quarantined' else 0.0)
            except OSError:pass
            rec=_qreg(base).get(d.name) if st=='quarantined' else None
            trusted=bool(rec)
            # 지우기 판단은 conf 의 신뢰 기록 시각만 — 기록 없는 격리 폴더(옛 판이 격리했거나 표식만 있는 것)는 알림·표시용으로만 표식 시각을 쓰고
            # 앱이 지우지 않는다(OS 관리자 몫). 표시까지 빼면 '격리 폴더 남음' 알림에서 조용히 사라진다(10-16 회귀 시험이 잡음)
            qz_at=(float(rec.get('at') or 0) if rec else _qz_since(d)) if st=='quarantined' else 0.0
            act=_action(st,newest,qz_at,busy) if (st!='quarantined' or trusted) else None
            out.append({'name':d.name,'state':st,'bytes':n,'files':c,'modified':newest,'quarantined_at':qz_at,
                        'action':act,'deletable':act is not None,'trusted':trusted if st=='quarantined' else None})
        except OSError:continue
    return out

def delete_backup(base,name,allow_delete=True):
    """관리자가 고른 임시 백업 폴더 하나를 정리한다. 주인 표식 없는 폴더는 바로 지우지 않고 격리(이름 바꾸기)한 뒤 10분 지나야 지운다(GPT 27차:
    '10분 조용함'은 백업이 끝났다는 증거가 아니다 — 격리하면 옛 판 백업이 아직 쓰고 있어도 그 백업만 실패한다. Windows 는 열린 파일이 있으면
    대개 이름 바꾸기를 거절하지만 공유 모드에 따라 허용될 수 있어 그것만으로 '안 쓰는 중'이라 보지 않는다(GPT 28차) — 격리 뒤 10분·변경 없음을 다시 본다).
    공통 확인: 이름 형식·바로 아래·링크 아님·하위 링크·정션 없음(지우기 직전 다시)·주인 살아 있으면 거절·10분 안에 바뀐 파일 있으면 거절·묶음(.partial) 쓰는 중 거절.
    지울 때는 먼저 이름을 바꾼 뒤(아무도 그 경로를 모름) 안을 다시 검사하고 지운다 — 검사와 삭제 사이에 끼어드는 일을 줄인다."""
    if not isinstance(name,str) or not _TMP_NAME.fullmatch(name):
        return {'ok':False,'error':'임시 백업 폴더 이름이 아닙니다'}
    base=Path(base).resolve();d=base/name
    if _is_link(d):return {'ok':False,'error':'링크·정션은 지우지 않습니다'}
    if not d.is_dir() or d.resolve().parent!=base:return {'ok':False,'error':'없는 폴더입니다'}
    st=_tmp_state(d)
    if st=='in_use':return {'ok':False,'error':'백업이 아직 돌고 있습니다(주인 프로세스 살아 있음)'}
    if st not in ('unowned','orphan','quarantined'):return {'ok':False,'error':'지울 수 없는 상태입니다'}
    if _has_link(d):return {'ok':False,'error':'안에 링크·정션이 있어 지우지 않습니다'}
    n,c,newest=_tmp_size(d)
    if st=='quarantined':
        if not allow_delete:
            return {'ok':False,'error':'로그인 없는(재인증할 수 없는) 모드에서는 앱에서 지우지 않습니다 — 격리 폴더는 OS 관리자가 직접 지우십시오','reauth':False}
        rec=_qreg(base).get(d.name)
        if not rec:return {'ok':False,'error':'격리 기록(conf/'+QREG+')에 없는 격리 폴더입니다 — 앱이 격리한 폴더만 지웁니다'}
        if content_digest(d)!=rec.get('sha'):return {'ok':False,'error':'격리한 뒤 폴더 내용이 바뀌었습니다(내용 지문 불일치) — 지우지 않습니다'}
        qz_at=float(rec.get('at') or 0)
        if not qz_at or time.time()-qz_at<QUIET_SEC:return {'ok':False,'error':'격리한 지 10분이 지나야 지울 수 있습니다'}
        if time.time()-newest<QUIET_SEC:return {'ok':False,'error':'격리한 뒤에도 바뀐 파일이 있습니다 — 무언가 아직 쓰고 있어 지우지 않습니다'}
    else:
        newest=max(newest,d.lstat().st_mtime)   # 빈 폴더도 막 만들어졌으면 쓰는 중일 수 있다
        if time.time()-newest<QUIET_SEC:return {'ok':False,'error':'10분 안에 바뀐 파일이 있습니다 — 쓰는 중일 수 있어 지우지 않습니다'}
        if _zip_busy(base):return {'ok':False,'error':'백업 묶음(.partial)을 쓰는 중입니다 — 끝난 뒤 다시 확인하십시오'}
    if st!='unowned' and _shared_writable(base,d):return {'ok':False,'error':SHARED_MSG}   # 지우기 전에 — 이름도 바꾸지 않고 돌려보낸다
    # 지울 때는 격리 폴더도 먼저 이름을 바꾼다(GPT 37차 — 검사와 삭제 사이 바꿔치기 줄이기): 바꾼 이름은 아무도 모른다
    target=(base/(d.name[:40]+'_D')) if st=='quarantined' else base/(QZ+name[len('.backup-'):])[:48]
    if target!=d:
        if target.exists():return {'ok':False,'error':'같은 이름의 격리 폴더가 이미 있습니다'}
        try:os.rename(d,target)
        except OSError:return {'ok':False,'error':'폴더를 옮길 수 없습니다 — 안의 파일을 무언가 열고 있어 지우지 않습니다'}
    if st=='unowned':
        at=time.time()
        (target/QZ_MARK).write_text(json.dumps({'at':at,'from':name}),encoding='utf-8')
        dg=content_digest(target)
        reg=_qreg(base);reg[target.name]={'at':at,'from':name,'sha':dg,'files':c,'bytes':n};_qreg_write(base,reg)
        return {'ok':True,'quarantined':True,'name':target.name,'bytes':n,'files':c,'sha':dg[:16]}
    if _is_link(target) or _has_link(target):return {'ok':False,'error':'안에 링크·정션이 있어 지우지 않습니다'}
    if _shared_writable(base,target):return {'ok':False,'error':SHARED_MSG}   # GPT 38차: 남이 끼어들 수 있는 폴더는 지우지 않는다
    done=[0]
    try:_rm_nofollow(target,done)   # 항목마다 다시 보고 링크는 따라가지 않는다
    except OSError as e:
        # GPT 41차 권고: 일부만 지웠으면 '지움'으로 적지 않는다 — 지운 수·남은 수·멈춘 까닭을 돌려주고(감사 기록에 들어감) 폴더는 남긴다
        try:_,left,_=_tmp_size(target)
        except OSError:left=-1
        why='권한' if isinstance(e,PermissionError) else '열림·잠김'
        return {'ok':False,'partial':True,'name':target.name,'deleted':done[0],'left':left,
                'error':f'일부만 지웠습니다 — {done[0]}개 지움 · {left}개 남음({why}) · 남은 폴더 {target.name[:48]} 를 확인하십시오'}
    reg=_qreg(base)
    if reg.pop(name,None) is not None:_qreg_write(base,reg)
    return {'ok':True,'name':name,'bytes':n,'files':c}

def _sweep_stale(base):
    """강제 종료로 남은 임시 백업 폴더(.backup-*) 정리 — 자료 사본이 들어 있어 남겨 두면 반출 묶음·디스크에 새어 나간다(2026-10-15).
    GPT 24차: 나이만 보고 지우면 1시간 넘게 도는 백업·동시 백업을 지울 수 있다 → 주인 표식(.owner: pid)의 프로세스가 끝난 것만 지운다.
    GPT 25차: 표식이 없는 폴더는 자동으로 지우지 않는다(stale_unowned — 관리자 확인). 링크·정션은 폴더 자체든 하위든 있으면 지우지 않는다."""
    if _shared_writable(base):return   # GPT 38차: 넓은 쓰기 권한이 있는 자료 폴더에서는 자동으로 지우지 않는다
    for d in Path(base).glob('.backup-*'):
        try:
            if _is_link(d) or not d.is_dir():continue
            own=d/OWNER
            if not own.is_file():continue
            try:pid=_owner_pid(own)
            except (OSError,ValueError):continue
            if pid is None or _alive(pid) or _has_link(d):continue
            _rm_nofollow(d)
        except OSError:pass

def snapshot(base,storage=None):
    base=Path(base).resolve();dest=base/'backups';dest.mkdir(exist_ok=True)
    _sweep_stale(base)
    with tempfile.TemporaryDirectory(prefix='.backup-',dir=base) as td:
        # 주인 표식은 묶을 자료(stage) 밖에 — 백업 묶음·검증에 섞이지 않게
        (Path(td)/OWNER).write_text(json.dumps({'pid':os.getpid(),'started':time.time()}),encoding='utf-8')
        stage=Path(td)/'stage'; stage.mkdir(); entries={}
        paths=[p for name in ROOTS for p in (base/name).rglob('*') if p.is_file()]
        paths += [base/n for n in FILES if (base/n).is_file()]
        for src in paths:
            if src.is_symlink() or not src.resolve().is_relative_to(base):raise ValueError('백업 경로의 외부 링크 거부')
            rel=src.relative_to(base).as_posix()
            # Lock/journal files, half-written outputs and in-flight analysis copies are never part of a snapshot (r2).
            if src.name.endswith(('-wal','-shm','.lock','.partial','.tmp')) or rel.startswith(TRANSIENT):continue
            dst=stage/rel;dst.parent.mkdir(parents=True,exist_ok=True)
            try:
                with src.open('rb') as f:isdb=f.read(16)==b'SQLite format 3\x00'
                if isdb:
                    source=sqlite3.connect(src.as_uri()+'?mode=ro',uri=True)
                    target=sqlite3.connect(dst)
                    try:source.backup(target)
                    finally:source.close();target.close()
                else:shutil.copy2(src,dst)
            except FileNotFoundError:
                dst.unlink(missing_ok=True);continue   # removed by a running job between listing and copy
            entries[rel]={'sha256':sha(dst),'sqlite':isdb}
        external=None
        if storage is not None and (storage.kind!='sqlite' or not storage.path.resolve().is_relative_to(base)):
            external=export_database(storage,stage/EXTERNAL_DUMP)
            entries[EXTERNAL_DUMP]={'sha256':sha(stage/EXTERNAL_DUMP),'sqlite':False}
        manifest={'schema':1,'created':datetime.now().astimezone().isoformat(),'files':entries,'roots':ROOTS,'consistency':'SQLite별 일관된 스냅샷; 여러 DB의 같은 시점 전역 스냅샷은 아님'}
        manifest['external_database']=external
        (stage/'backup-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False),encoding='utf-8')
        name='backup-'+datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:6]+'.zip'
        partial=dest/(name+'.partial');final=dest/name
        with zipfile.ZipFile(partial,'w',zipfile.ZIP_DEFLATED) as z:
            for p in stage.rglob('*'):
                if p.is_file():z.write(p,p.relative_to(stage).as_posix())
        os.chmod(partial,0o600)
        verify(partial)
        partial.replace(final)
        (dest/(name+'.sha256')).write_text(sha(final)+'  '+name+'\n',encoding='ascii')
        return {'file':str(final),'files':len(entries),'sha256':sha(final),'verified':True}

def unpack_checked(archive,dest):
    with zipfile.ZipFile(archive) as z:
        seen=set();total=0
        for info in z.infolist():
            n=info.filename;p=PurePosixPath(n);total+=info.file_size
            if n in seen or p.is_absolute() or '..' in p.parts or '\\' in n or ':' in n or total>20*1024**3:raise ValueError('안전하지 않은 백업 ZIP')
            seen.add(n)
            if info.is_dir():continue
            dst=dest.joinpath(*p.parts);dst.parent.mkdir(parents=True,exist_ok=True)
            with z.open(info) as f,dst.open('wb') as out:shutil.copyfileobj(f,out)
    m=json.loads((dest/'backup-manifest.json').read_text(encoding='utf-8'))
    if set(seen)-{'backup-manifest.json'} != set(m['files']):raise ValueError('백업 목록 불일치')
    for n,v in m['files'].items():
        p=dest/n
        if sha(p)!=v['sha256']:raise ValueError('백업 해시 불일치')
        if v['sqlite']:
            db=sqlite3.connect(p)
            try:
                if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('백업 DB 무결성 실패')
            finally:db.close()
    return m

def verify(archive):
    with tempfile.TemporaryDirectory(prefix='lt-backup-check-') as td:return unpack_checked(archive,Path(td))

def restore(base,archive,offline=False,storage=None):
    if not offline:raise ValueError('서버와 PC 프로그램 종료 후 --offline-confirmed 필요')
    base=Path(base).resolve()
    from .automation import InstanceLock
    lock=InstanceLock(base/'.automation-worker.lock');lock.acquire()
    try:
        with tempfile.TemporaryDirectory(prefix='.restore-',dir=base) as td:
            stage=Path(td)/'stage';stage.mkdir();m=unpack_checked(archive,stage)
            external=m.get('external_database')
            if external and (storage is None or storage.kind!=external['kind']):
                raise ValueError('이 백업의 외부 분석 DB 복원에는 같은 종류의 --db 또는 LOGTRIAGE_DB가 필요합니다')
            tops=set(n.split('/')[0] for n in m['files'])
            if not tops<=set(ROOTS+FILES):raise ValueError('복원 허용 경로 외 파일')
            # Worker lock is outside swapped paths for backup restore operations.
            if (stage/'data/automation/worker.lock').exists():raise ValueError('백업에 잠금 파일 포함')
            backup=base/('restore-rollback-'+uuid.uuid4().hex);backup.mkdir();swapped=[]
            try:
                for name in sorted(tops):
                    target=base/name
                    if target.is_symlink():raise ValueError('복원 경로 링크 거부')
                    if target.exists():target.rename(backup/name)
                    swapped.append(name);(stage/name).rename(target)
                if external:import_database(storage,base/EXTERNAL_DUMP)
            except Exception:
                for name in reversed(swapped):
                    target=base/name
                    if target.is_dir():shutil.rmtree(target)
                    elif target.exists():target.unlink()
                    if (backup/name).exists():(backup/name).rename(target)
                raise
            return {'restored':len(m['files']),'rollback':str(backup)}
    finally:lock.release()
