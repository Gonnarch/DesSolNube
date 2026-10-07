import base64, hashlib, hmac, json, os, re, secrets, sqlite3, struct, time
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode, quote
from urllib.request import Request, urlopen
from http.cookies import SimpleCookie

ROOT=Path(__file__).parent
DB=ROOT/'techstore.sqlite'
ORIGIN='http://127.0.0.1:8765'
KEYFILE=ROOT/'signing.key'
if not KEYFILE.exists(): KEYFILE.write_bytes(secrets.token_bytes(32))
KEY=KEYFILE.read_bytes()
ROLES=['Administrador','Gerente','Empleado','Auditor']
def conn():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def initialize():
 with conn() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,name TEXT,store TEXT,role TEXT,password TEXT,totp TEXT,enabled INTEGER DEFAULT 0,failures INTEGER DEFAULT 0,locked REAL DEFAULT 0,last_step INTEGER DEFAULT -1);
  CREATE TABLE IF NOT EXISTS challenges(id TEXT PRIMARY KEY,uid INTEGER,expires REAL,attempts INTEGER DEFAULT 0,used INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,uid INTEGER,expires REAL);
  CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT,store TEXT,price REAL,stock INTEGER);
  CREATE TABLE IF NOT EXISTS oauth(state TEXT PRIMARY KEY,provider TEXT,verifier TEXT,expires REAL);
  CREATE TABLE IF NOT EXISTS identities(provider TEXT,subject TEXT,uid INTEGER,PRIMARY KEY(provider,subject));
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at TEXT,event TEXT,detail TEXT);''')
  if not c.execute('SELECT 1 FROM products').fetchone(): c.executemany('INSERT INTO products(name,store,price,stock) VALUES(?,?,?,?)',[('Laptop ThinkPad E14','Lima',3299,12),('Monitor LG 24 pulgadas','Lima',649,24),('Teclado Logitech K380','Arequipa',179,35)])
  if 'method' not in [x[1] for x in c.execute('PRAGMA table_info(challenges)')]:c.execute("ALTER TABLE challenges ADD COLUMN method TEXT DEFAULT 'pwd'")
def audit(event,detail):
 with conn() as c:c.execute('INSERT INTO audit(at,event,detail) VALUES(?,?,?)',(time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),event,detail))
def b64(v):return base64.urlsafe_b64encode(v).rstrip(b'=').decode()
def unb64(v):return base64.urlsafe_b64decode(v+'='*(-len(v)%4))
def password_hash(p,salt=None):
 salt=salt or secrets.token_hex(16)
 return salt+':'+hashlib.pbkdf2_hmac('sha256',p.encode(),salt.encode(),600000).hex()
def valid_password(p):return len(p)>=8 and bool(re.search('[A-Z]',p)) and bool(re.search('[0-9]',p)) and bool(re.search(r'[^a-zA-Z0-9\s]',p))
def totp(secret,step=None,digits=6):
 step=int(time.time()//30) if step is None else step
 raw=hmac.new(base64.b32decode(secret),struct.pack('>Q',step),hashlib.sha1).digest(); offset=raw[-1]&15
 return str((struct.unpack('>I',raw[offset:offset+4])[0]&0x7fffffff)%10**digits).zfill(digits)
def jwt_make(uid,sid,method='pwd'):
 payload={'sub':str(uid),'sid':sid,'iss':'techstore-local','aud':'techstore','iat':int(time.time()),'exp':int(time.time())+1800,'amr':[method,'otp']}
 head=b64(json.dumps({'alg':'HS256','typ':'JWT'},separators=(',',':')).encode()); body=b64(json.dumps(payload,separators=(',',':')).encode()); msg=head+'.'+body
 return msg+'.'+b64(hmac.new(KEY,msg.encode(),hashlib.sha256).digest())
def jwt_read(token):
 a,b,s=token.split('.'); msg=a+'.'+b
 if not hmac.compare_digest(b64(hmac.new(KEY,msg.encode(),hashlib.sha256).digest()),s):raise ValueError('Firma inválida')
 if json.loads(unb64(a)).get('alg')!='HS256':raise ValueError('Algoritmo inválido')
 p=json.loads(unb64(b))
 if p['exp']<=time.time() or p['iss']!='techstore-local' or p['aud']!='techstore':raise ValueError('Token inválido')
 return p
def public(u):return {k:u[k] for k in ['id','email','name','store','role']}
def challenge(uid,method='pwd'):
 cid=secrets.token_urlsafe(32)
 with conn() as c:
  c.execute('UPDATE challenges SET used=1 WHERE uid=?',(uid,)); c.execute('INSERT INTO challenges(id,uid,expires,method) VALUES(?,?,?,?)',(cid,uid,time.time()+300,method));u=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
 result={'challenge':cid,'mfa_required':True,'enrollment':not bool(u['enabled']),'message':'Credenciales correctas. Completa la verificación de dos pasos.','digits':6,'period':30,'max_attempts':3}
 if not u['enabled']:
  result['secret']=u['totp'];result['uri']='otpauth://totp/TechStore:'+quote(u['email'])+'?'+urlencode({'secret':u['totp'],'issuer':'TechStore','digits':6,'period':30})
 return result
def config():
 p=ROOT/'oauth-config.json'
 return json.loads(p.read_text()) if p.exists() else {}
def remote_json(url,data=None,headers=None):
 hdr={'Accept':'application/json','User-Agent':'TechStore-Lab'};hdr.update(headers or {})
 if data is not None: hdr['Content-Type']='application/x-www-form-urlencoded'
 with urlopen(Request(url,data=urlencode(data).encode() if data is not None else None,headers=hdr),timeout=20) as r:return json.load(r)

class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def send(self,status,data,cookie=None):
  raw=json.dumps(data,ensure_ascii=False).encode();self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(raw)
 def redirect(self,url,cookie=None):
  self.send_response(302);self.send_header('Location',url)
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers()
 def user(self):
  cookies=SimpleCookie(self.headers.get('Cookie',''));token=self.headers.get('Authorization','').removeprefix('Bearer ') or (cookies['session'].value if 'session' in cookies else '')
  try:
   p=jwt_read(token)
   with conn() as c:
    s=c.execute('SELECT * FROM sessions WHERE id=? AND expires>?',(p['sid'],time.time())).fetchone()
    if not s or str(s['uid'])!=p['sub']:return None
    return c.execute('SELECT * FROM users WHERE id=?',(s['uid'],)).fetchone()
  except Exception:return None
 def do_GET(self):
  path=urlparse(self.path).path
  assets={'/assets/theme.css':('theme.css','text/css; charset=utf-8'),'/assets/theme.js':('theme.js','text/javascript; charset=utf-8'),'/assets/techstore-background.png':('techstore-background.png','image/png')}
  if path in assets:
   filename,mime=assets[path];p=ROOT/filename
   if not p.is_file():return self.send(404,{'error':'Recurso no encontrado'})
   self.send_response(200);self.send_header('Content-Type',mime);self.send_header('Cache-Control','no-cache');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(p.read_bytes());return
  if path in ['/','/configurar','/evidencias','/autenticador']:
   name={'/':'index.html','/configurar':'config.html','/evidencias':'evidence.html','/autenticador':'authenticator.html'}[path]
   p=ROOT/name
   if not p.exists():return self.send(404,{'error':'No encontrado'})
   self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('X-Frame-Options','DENY');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(p.read_bytes());return
  if path=='/api/config':return self.send(200,{'google':bool(config().get('google_id') and config().get('google_secret')),'github':bool(config().get('github_id') and config().get('github_secret')),'origin':ORIGIN})
  if path=='/api/evidence':
   p=ROOT/'results.json';return self.send(200,json.loads(p.read_text(encoding='utf-8')) if p.exists() else [])
  if path.startswith('/auth/'):
   return self.oauth(path)
  u=self.user()
  if not u:return self.send(401,{'error':'Se requiere una sesión con MFA completado.'})
  if path=='/api/me':return self.send(200,{'user':public(u),'mfa_verified':True})
  if path in ['/api/products','/api/report']:
   if path=='/api/report' and u['role']=='Empleado':return self.send(403,{'error':'El empleado no puede generar reportes.'})
   with conn() as c:rows=c.execute('SELECT * FROM products'+(' WHERE store=?' if u['role'] in ['Gerente','Empleado'] else ''),(u['store'],) if u['role'] in ['Gerente','Empleado'] else ()).fetchall()
   return self.send(200,{'products':[dict(x) for x in rows],'scope':u['store'] if u['role'] in ['Gerente','Empleado'] else 'Todas las tiendas'})
  if path=='/api/users':
   if u['role']!='Administrador':return self.send(403,{'error':'Solo el administrador puede gestionar usuarios.'})
   with conn() as c:rows=c.execute('SELECT * FROM users').fetchall()
   return self.send(200,{'users':[public(x) for x in rows]})
  return self.send(404,{'error':'No encontrado'})
 def do_POST(self):
  if self.headers.get('Origin') not in [None,ORIGIN]:return self.send(403,{'error':'Origen no permitido'})
  try:
   size=int(self.headers.get('Content-Length','0'))
   if size>20000:return self.send(413,{'error':'Solicitud demasiado grande'})
   d=json.loads(self.rfile.read(size) or b'{}')
   return self.post(urlparse(self.path).path,d)
  except (ValueError,KeyError,TypeError):return self.send(400,{'error':'Datos inválidos'})
  except Exception as e:
   audit('error',type(e).__name__);return self.send(500,{'error':'No se pudo completar la operación.'})
 def post(self,path,d):
  if path=='/api/config':
   allowed=['google_id','google_secret','github_id','github_secret']
   if any(not isinstance(d.get(x,''),str) for x in allowed):return self.send(400,{'error':'Datos inválidos'})
   cfg=config();cfg.update({x:d[x].strip() for x in allowed if d.get(x,'').strip()});(ROOT/'oauth-config.json').write_text(json.dumps(cfg))
   return self.send(200,{'message':'Configuración guardada localmente.'})
  if path=='/api/register':
   email=d.get('email','').strip().lower();p=d.get('password','');name=d.get('name','').strip();store=d.get('store','')
   if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or not name or store not in ['Lima','Arequipa']:return self.send(400,{'error':'Completa un correo válido, nombre y tienda.'})
   if not valid_password(p):return self.send(400,{'error':'La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un carácter especial.'})
   try:
    with conn() as c:
     c.execute('INSERT INTO users(email,name,store,role,password,totp) VALUES(?,?,?,?,?,?)',(email,name,store,'Empleado',password_hash(p),base64.b32encode(secrets.token_bytes(20)).decode()))
     u=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
   except sqlite3.IntegrityError:return self.send(409,{'error':'El correo ya está registrado.'})
   audit('registro',email);return self.send(201,{'message':'Usuario registrado correctamente. Inicia sesión para activar MFA.','user':public(u)})
  if path=='/api/login':
   email=d.get('email','').strip().lower();p=d.get('password','')
   with conn() as c:
    c.execute('BEGIN IMMEDIATE');u=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
    if not u:
     password_hash(p);return self.send(401,{'error':'Credenciales incorrectas.'})
    if u['locked']>time.time():return self.send(423,{'error':'Cuenta bloqueada después de 5 intentos. Intenta de nuevo en 15 minutos.','attempts':5})
    if not u['password'] or not hmac.compare_digest(password_hash(p,u['password'].split(':')[0]),u['password']):
     n=(0 if u['locked'] else u['failures'])+1;c.execute('UPDATE users SET failures=?,locked=? WHERE id=?',(n,time.time()+900 if n>=5 else 0,u['id']));c.commit()
     return self.send(423 if n>=5 else 401,{'error':'Cuenta bloqueada después de 5 intentos. Intenta de nuevo en 15 minutos.' if n>=5 else 'Credenciales incorrectas.','attempts':n,'remaining':max(0,5-n)})
    c.execute('UPDATE users SET failures=0,locked=0 WHERE id=?',(u['id'],))
   audit('credenciales_correctas',email);return self.send(200,challenge(u['id']))
  if path=='/api/mfa':
   cid=d.get('challenge','');code=d.get('code','')
   with conn() as c:
    c.execute('BEGIN IMMEDIATE');ch=c.execute('SELECT * FROM challenges WHERE id=?',(cid,)).fetchone()
    if not ch or ch['used'] or ch['expires']<time.time():return self.send(401,{'error':'Verificación vencida o bloqueada. Inicia sesión de nuevo.'})
    u=c.execute('SELECT * FROM users WHERE id=?',(ch['uid'],)).fetchone();step=int(time.time()//30)
    ok=bool(re.fullmatch('[0-9]{6}',code)) and hmac.compare_digest(totp(u['totp'],step),code) and step>u['last_step']
    if not ok:
     n=ch['attempts']+1;c.execute('UPDATE challenges SET attempts=?,used=? WHERE id=?',(n,int(n>=3),cid));c.commit()
     return self.send(403 if n>=3 else 401,{'error':'Verificación bloqueada tras 3 intentos incorrectos. Inicia sesión de nuevo.' if n>=3 else 'Código incorrecto, vencido o ya utilizado.','attempts':n,'remaining':max(0,3-n)})
    c.execute('UPDATE challenges SET used=1 WHERE id=?',(cid,));c.execute('UPDATE users SET enabled=1,last_step=? WHERE id=?',(step,u['id']));sid=secrets.token_urlsafe(32);c.execute('INSERT INTO sessions VALUES(?,?,?)',(sid,u['id'],time.time()+1800))
   token=jwt_make(u['id'],sid,ch['method']);audit('mfa_correcto',u['email']);return self.send(200,{'message':'Acceso concedido. MFA verificado.','user':public(u),'token':token,'token_type':'Bearer','expires_in':1800},'session='+token+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800')
  u=self.user()
  if not u:return self.send(401,{'error':'Se requiere una sesión con MFA completado.'})
  if path=='/api/logout':
   cookies=SimpleCookie(self.headers.get('Cookie',''))
   if 'session' in cookies:
    p=jwt_read(cookies['session'].value)
    with conn() as c:c.execute('DELETE FROM sessions WHERE id=?',(p['sid'],))
   return self.send(200,{'message':'Sesión cerrada.'},'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')
  if path=='/api/users/update':
   if u['role']!='Administrador':return self.send(403,{'error':'Solo el administrador puede gestionar usuarios.'})
   if d['role'] not in ROLES or d['store'] not in ['Lima','Arequipa']:return self.send(400,{'error':'Rol o tienda inválidos.'})
   with conn() as c:
    c.execute('UPDATE users SET role=?,store=? WHERE id=?',(d['role'],d['store'],int(d['id'])));c.execute('DELETE FROM sessions WHERE uid=?',(int(d['id']),))
   return self.send(200,{'message':'Usuario actualizado. Sus sesiones se cerraron.'})
  if path=='/api/products/create':
   if u['role'] not in ['Administrador','Gerente']:return self.send(403,{'error':'Este rol no puede crear productos.'})
   store=d['store'] if u['role']=='Administrador' else u['store'];price=float(d['price']);stock=int(d['stock'])
   if price<0 or stock<0 or store not in ['Lima','Arequipa'] or not d['name'].strip():return self.send(400,{'error':'Producto inválido.'})
   with conn() as c:c.execute('INSERT INTO products(name,store,price,stock) VALUES(?,?,?,?)',(d['name'],store,price,stock))
   return self.send(201,{'message':'Producto creado.'})
  if path in ['/api/products/update','/api/products/delete']:
   with conn() as c:
    product=c.execute('SELECT * FROM products WHERE id=?',(int(d['id']),)).fetchone()
    if not product:return self.send(404,{'error':'Producto no encontrado.'})
    if u['role']=='Auditor':return self.send(403,{'error':'Auditor: acceso de solo lectura. No puede modificar datos.'})
    if u['role']!='Administrador' and product['store']!=u['store']:return self.send(403,{'error':'No tienes permiso para modificar productos de otra tienda.'})
    if u['role']=='Empleado' and (path.endswith('delete') or set(d)-{'id','stock'}):return self.send(403,{'error':'Empleado: puede actualizar stock, pero no modificar precios ni eliminar productos.'})
    if path.endswith('delete'):c.execute('DELETE FROM products WHERE id=?',(product['id'],))
    else:
     price=float(d.get('price',product['price']));stock=int(d.get('stock',product['stock']))
     if price<0 or stock<0:return self.send(400,{'error':'Precio y stock deben ser no negativos.'})
     c.execute('UPDATE products SET price=?,stock=? WHERE id=?',(price,stock,product['id']))
   return self.send(200,{'message':'Producto eliminado.' if path.endswith('delete') else 'Producto actualizado.','id':product['id']})
  return self.send(404,{'error':'No encontrado'})
 def oauth(self,path):
  parts=path.strip('/').split('/');provider=parts[1]
  if provider not in ['google','github']:return self.send(404,{'error':'Proveedor inválido'})
  cfg=config();client=cfg.get(provider+'_id');secret=cfg.get(provider+'_secret');callback=ORIGIN+'/auth/'+provider+'/callback'
  if not client or not secret:return self.send(503,{'error':'Falta configurar la aplicación OAuth de '+provider+'. Abre /configurar.'})
  if len(parts)==2:
   state=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
   with conn() as c:c.execute('INSERT INTO oauth VALUES(?,?,?,?)',(state,provider,verifier,time.time()+600))
   params={'client_id':client,'redirect_uri':callback,'state':state,'response_type':'code','code_challenge':b64(hashlib.sha256(verifier.encode()).digest()),'code_challenge_method':'S256','scope':'openid email profile' if provider=='google' else 'read:user user:email'}
   return self.redirect(('https://accounts.google.com/o/oauth2/v2/auth' if provider=='google' else 'https://github.com/login/oauth/authorize')+'?'+urlencode(params),'oauth_state='+state+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=600')
  q=parse_qs(urlparse(self.path).query);state=q.get('state',[''])[0];cookies=SimpleCookie(self.headers.get('Cookie',''))
  if 'oauth_state' not in cookies or not hmac.compare_digest(cookies['oauth_state'].value,state):return self.send(403,{'error':'Estado OAuth inválido.'})
  with conn() as c:
   flow=c.execute('SELECT * FROM oauth WHERE state=? AND provider=? AND expires>?',(state,provider,time.time())).fetchone();c.execute('DELETE FROM oauth WHERE state=?',(state,))
  if not flow or not q.get('code'):return self.send(400,{'error':'Autorización cancelada o vencida.'})
  try:
   token=remote_json('https://oauth2.googleapis.com/token' if provider=='google' else 'https://github.com/login/oauth/access_token',{'client_id':client,'client_secret':secret,'code':q['code'][0],'redirect_uri':callback,'grant_type':'authorization_code','code_verifier':flow['verifier']})['access_token'];hdr={'Authorization':'Bearer '+token}
   profile=remote_json('https://openidconnect.googleapis.com/v1/userinfo' if provider=='google' else 'https://api.github.com/user',headers=hdr)
   if provider=='google':
    if not profile.get('email_verified'):raise ValueError('Correo no verificado')
    email=profile['email'];subject=profile['sub']
   else:
    emails=remote_json('https://api.github.com/user/emails',headers=hdr);email=next(x['email'] for x in emails if x['primary'] and x['verified']);subject=str(profile['id'])
   with conn() as c:
    identity=c.execute('SELECT uid FROM identities WHERE provider=? AND subject=?',(provider,subject)).fetchone()
    if identity:uid=identity['uid']
    else:
     if c.execute('SELECT id FROM users WHERE email=?',(email.lower(),)).fetchone():return self.send(409,{'error':'Este correo ya pertenece a una cuenta. Usa su método original de acceso; no se vinculan cuentas automáticamente.'})
     cur=c.execute('INSERT INTO users(email,name,store,role,password,totp) VALUES(?,?,?,?,?,?)',(email.lower(),profile.get('name') or profile.get('login') or email,'Lima','Empleado','',base64.b32encode(secrets.token_bytes(20)).decode()));uid=cur.lastrowid;c.execute('INSERT INTO identities VALUES(?,?,?)',(provider,subject,uid))
   data=challenge(uid);audit('oauth_correcto',provider)
   # A short-lived challenge is passed in the fragment; no provider token is exposed.
   return self.redirect('/#oauth='+quote(json.dumps(data)),'oauth_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')
  except Exception:return self.send(502,{'error':'El proveedor no pudo validar el acceso. Revisa la configuración OAuth.'})

if __name__=='__main__':
 initialize();print('TechStore: '+ORIGIN,flush=True);ThreadingHTTPServer(('127.0.0.1',8765),Handler).serve_forever()
