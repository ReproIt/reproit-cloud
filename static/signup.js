var params=new URLSearchParams(location.search),next=(function(){var n=params.get('next')||'';return n&&n[0]==='/'&&n.slice(0,2)!=='//'&&!n.startsWith('/signup')?n:''})(),invite='';
if(next.startsWith('/invite?'))invite=(new URL(next,'http://local')).searchParams.get('token')||'';
var emailParam=params.get('email')||'';if(emailParam){document.getElementById('email').value=emailParam;document.getElementById('email').readOnly=true}
var signin=document.querySelector('.alt a');if(signin&&next)signin.href='/login?next='+encodeURIComponent(next);
var form=document.getElementById('form'), msg=document.getElementById('msg'), btn=document.getElementById('submit');
form.addEventListener('submit', async function(e){
  e.preventDefault();
  msg.className='msg'; msg.textContent='';
  btn.disabled=true; btn.textContent='Creating…';
  try{
    var r=await fetch('/auth/signup',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value,invite:invite||undefined})});
    var d=await r.json().catch(function(){return {};});
    if(r.ok){ location.href=next||'/app'; return; }
    msg.className='msg err'; msg.textContent=d.error||'Could not create account';
  }catch(err){ msg.className='msg err'; msg.textContent='Network error, try again'; }
  btn.disabled=false; btn.textContent='Create account →';
});
