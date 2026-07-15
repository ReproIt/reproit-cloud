var params=new URLSearchParams(location.search);
function safeNext(){
  var next=params.get('next')||'';
  if(!next||next[0]!=='/'||next.slice(0,2)==='//'||next.startsWith('/login')) return '';
  return next;
}
var next=safeNext();
var invite='';if(next.startsWith('/invite?'))invite=(new URL(next,'http://local')).searchParams.get('token')||'';
var signup=document.querySelector('.alt a');
if(signup&&next) signup.href='/signup?next='+encodeURIComponent(next);
var form=document.getElementById('form'), msg=document.getElementById('msg'), btn=document.getElementById('submit');
form.addEventListener('submit', async function(e){
  e.preventDefault();
  msg.className='msg'; msg.textContent=''; btn.disabled=true; btn.textContent='Signing in…';
  try{
    var r=await fetch('/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value,invite:invite||undefined,orgId:(function(){try{return Number(localStorage.getItem('reproit.activeOrg'))||undefined}catch(e){return undefined}})()})});
    var d=await r.json().catch(function(){return {};});
    if(r.ok){ location.href=next||'/app'; return; }
    msg.className='msg err'; msg.textContent=d.error||'Could not sign in';
  }catch(err){ msg.className='msg err'; msg.textContent='Network error, try again'; }
  btn.disabled=false; btn.textContent='Sign in →';
});
