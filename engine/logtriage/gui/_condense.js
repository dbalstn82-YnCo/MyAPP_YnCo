/* 긴 안내문 접기(17차, 마스터: '간결한 문구 — 불필요한 텍스트는 과감히 삭제하거나 안내·도움말로'). 모든 화면 공통, 원본은 이 파일 한 곳.
   90자가 넘는 안내문(.help · p.note · div.note)은 한 줄만 보이고 [ⓘ 자세히]로 펼친다. 글을 지우거나 옮기지 않는다 — 화면 낭독기는 전문을 읽는다.
   건드리지 않는 것: 오류·상태 알림(role=alert/status·aria-live), 빈 화면 안내(.empty), 표 칸, 결과 카드, id 가 붙은 글(화면이 바꿔 쓰는 상태 글),
   단추·입력·링크·표·목록을 품은 글(접으면 조작할 것이 숨는다), data-keep 표시. 나중에 그려지는 글도 MutationObserver 로 같은 규칙. */
(function(){
  if(window.__ltCondense) return; window.__ltCondense=1;
  var MIN=90, SEL='.help,p.note,div.note';
  var SKIP='[role=alert],[role=status],[aria-live],.okbox,.errbox,.empty,.copybox,.repdone,.repfail,.explain,td,th,[data-keep],#lt-up,#lt-pal,details,.warn,.crit,.danger,.bad,[style*="--crit"],[style*="--warn"]';
  // 시안(GPT 112): 한 줄 안내 띠 오른쪽 끝에 [ⓘ 자세히], 펼치면 오른쪽 위 [접기 ▲]. 접힌 상태는 한 줄 + '…'(둘째 줄을 그리지 않음)
  var CSS='.ltc{position:relative;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-right:76px!important}.ltc *{white-space:nowrap}'+
    '.ltc.ltc-open{white-space:normal;overflow:visible;text-overflow:clip}.ltc.ltc-open *{white-space:normal}'+
    '.ltc-btn{all:unset;cursor:pointer;position:absolute;right:8px;top:50%;transform:translateY(-50%);font-size:12px;font-weight:700;color:#1A5FD0;white-space:nowrap;border-radius:6px;padding:1px 4px;background:inherit}'+
    '.ltc.ltc-open .ltc-btn{top:6px;transform:none}.ltc-btn:hover{text-decoration:underline}.ltc-btn:focus-visible{outline:2px solid #1A5FD0;outline-offset:1px}'+
    '@media print{.ltc,.ltc *{white-space:normal!important;overflow:visible!important}.ltc{padding-right:0!important}.ltc-btn{display:none}}';
  function css(){ if(document.getElementById('lt-ltc-css')) return; try{ var st=window.ltStyleEl?window.ltStyleEl():document.createElement('style'); st.id='lt-ltc-css'; st.textContent=CSS; document.head.appendChild(st); }catch(e){} }
  function eligible(el){
    if(el.getAttribute('data-ltc')||(el.id&&!el.classList.contains('help'))||el.closest(SKIP)) return false;   // id 붙은 .note 는 화면이 바꿔 쓰는 상태 글 — .help 상자는 안내라 접는다
    if(el.querySelector('input,select,textarea,button,a,details,canvas,svg,table,ul,ol,pre')) return false;
    var t=(el.textContent||'').replace(/\s+/g,' ').trim();
    // GPT 113 P0 조건부: 삭제·영구·복구 불가·권한 부여·외부 전송·비밀값 노출 같은 위험 안내는 글자 수와 상관없이 늘 펼쳐 둔다
    if(/^[⚠✖❗!]/.test(t)||/위험|주의|경고|되돌릴 수 없|복구할 수 없|영구|삭제|비밀번호|인증키|개인키|토큰|외부로|전송/.test(t)) return false;
    return t.length>=MIN;
  }
  var OPEN={}, seq=0;   // 다시 그려져도 펼친 상태 유지(같은 첫머리 글 = 같은 안내)
  function key(el){ return (el.textContent||'').replace(/\s+/g,' ').trim().slice(0,60); }
  function apply(el){
    el.setAttribute('data-ltc','1'); el.classList.add('ltc'); if(!el.id) el.id='ltc-'+(++seq);
    var k=key(el), open=!!OPEN[k]; if(open) el.classList.add('ltc-open');
    var b=document.createElement('button'); b.type='button'; b.className='ltc-btn'; b.textContent=open?'접기 ▲':'ⓘ 자세히'; b.setAttribute('aria-expanded',String(open)); b.setAttribute('aria-controls',el.id);
    b.addEventListener('click',function(e){ e.stopPropagation(); var o=el.classList.toggle('ltc-open'); if(o) OPEN[k]=1; else delete OPEN[k]; b.textContent=o?'접기 ▲':'ⓘ 자세히'; b.setAttribute('aria-expanded',String(o)); });
    el.appendChild(b);
  }
  function scan(root){
    var list=[]; if(root.matches&&root.matches(SEL)) list.push(root);
    if(root.querySelectorAll) list=list.concat([].slice.call(root.querySelectorAll(SEL)));
    for(var i=0;i<list.length;i++){ try{ if(eligible(list[i])) apply(list[i]); }catch(e){} }
  }
  var pend=[], t=0;
  function flush(){ t=0; var p=pend; pend=[]; for(var i=0;i<p.length;i++) if(p[i].isConnected) scan(p[i]); }
  function start(){
    css(); scan(document.body);
    try{ new MutationObserver(function(ms){ for(var i=0;i<ms.length;i++) for(var j=0;j<ms[i].addedNodes.length;j++){ var n=ms[i].addedNodes[j]; if(n.nodeType===1&&!(n.classList&&n.classList.contains('ltc-btn'))) pend.push(n); }
      if(pend.length&&!t) t=setTimeout(flush,120); }).observe(document.body,{childList:true,subtree:true}); }catch(e){}
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',start); else start();
})();
