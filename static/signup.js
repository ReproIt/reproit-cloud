var form=document.getElementById('form'), msg=document.getElementById('msg'), btn=document.getElementById('submit');
form.addEventListener('submit', async function(e){
  e.preventDefault();
  msg.className='msg'; msg.textContent='';
  btn.disabled=true; btn.textContent='Creating…';
  try{
    var r=await fetch('/auth/signup',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});
    var d=await r.json().catch(function(){return {};});
    if(r.ok){ location.href='/app'; return; }
    msg.className='msg err'; msg.textContent=d.error||'Could not create account';
  }catch(err){ msg.className='msg err'; msg.textContent='Network error, try again'; }
  btn.disabled=false; btn.textContent='Create account →';
});
