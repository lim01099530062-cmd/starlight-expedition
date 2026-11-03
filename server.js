'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const ROOT=__dirname, PORT=Number(process.env.PORT||3000), DB=path.join(ROOT,'data','players.json');
const sessions=new Map(),online=new Map();
const USE_PG=Boolean(process.env.DATABASE_URL);
const USE_LOCAL=process.env.ALLOW_LOCAL_STORAGE==='1';
if(!USE_PG&&!USE_LOCAL){console.error('DATABASE_URL is required: refusing ephemeral account storage');process.exit(1)}
const pool=USE_PG?new (require('pg').Pool)({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:{rejectUnauthorized:false}}):null;
const accounts=USE_LOCAL&&fs.existsSync(DB)?JSON.parse(fs.readFileSync(DB,'utf8')):{};
async function initialize(){if(pool)await pool.query(`CREATE TABLE IF NOT EXISTS game_accounts (name VARCHAR(20) PRIMARY KEY, salt TEXT NOT NULL, pass TEXT NOT NULL, game JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`)}
async function getAccount(name){if(pool){const r=await pool.query('SELECT salt,pass,game FROM game_accounts WHERE name=$1',[name]);return r.rows[0]||null}return accounts[name]||null}
async function createAccount(name,salt,pass,game){if(pool){const r=await pool.query('INSERT INTO game_accounts(name,salt,pass,game) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT DO NOTHING RETURNING name',[name,salt,pass,JSON.stringify(game)]);return r.rowCount===1}if(accounts[name])return false;accounts[name]={salt,pass,game};saveLocal();return true}
async function saveGame(name,game){if(pool){const r=await pool.query('UPDATE game_accounts SET game=$2::jsonb,updated_at=NOW() WHERE name=$1',[name,JSON.stringify(game)]);return r.rowCount===1}if(!accounts[name])return false;accounts[name].game=game;saveLocal();return true}
function saveLocal(){fs.mkdirSync(path.dirname(DB),{recursive:true});const tmp=DB+'.tmp';fs.writeFileSync(tmp,JSON.stringify(accounts));fs.renameSync(tmp,DB)}
const hash=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
function json(res,status,obj){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj))}
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2))}
function auth(req){const sid=cookies(req).sid,session=sessions.get(sid);if(!session||session.expires<Date.now())return null;session.expires=Date.now()+86400000;online.set(session.name,Date.now());return session.name}
function body(req){return new Promise((resolve,reject)=>{let data='';req.on('data',c=>{data+=c;if(data.length>1000000){reject(Error('too large'));req.destroy()}});req.on('end',()=>{try{resolve(JSON.parse(data||'{}'))}catch{reject(Error('bad json'))}})})}
function fresh(){return {version:2,level:1,xp:0,gold:200,gems:1200,stage:1,chapter:1,kills:0,attack:12,maxHp:110,hp:110,weaponLevel:0,armorLevel:0,gear:[],equipped:{},allies:[],pets:[],party:[],pet:null,stars:{},bossAuto:false,log:[],lastSeen:Date.now()}}
const mime={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost'),p=url.pathname;
if(p==='/api/health')return json(res,200,{ok:true});
if(p==='/api/register'&&req.method==='POST'){const b=await body(req),name=String(b.name||'').trim(),pw=String(b.password||'');if(!/^[a-zA-Z0-9_]{3,20}$/.test(name)||pw.length<8||pw.length>128)return json(res,400,{error:'아이디 3~20자(영문/숫자/_) 및 비밀번호 8자 이상 필요'});const salt=crypto.randomBytes(16).toString('hex');if(!await createAccount(name,salt,hash(pw,salt),fresh()))return json(res,409,{error:'이미 사용 중인 아이디입니다'});return json(res,200,{ok:true})}
if(p==='/api/login'&&req.method==='POST'){const b=await body(req),name=String(b.name||''),a=await getAccount(name);if(!a||!crypto.timingSafeEqual(Buffer.from(a.pass,'hex'),Buffer.from(hash(String(b.password||''),a.salt),'hex')))return json(res,401,{error:'아이디 또는 비밀번호가 올바르지 않습니다'});const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{name,expires:Date.now()+86400000});online.set(name,Date.now());res.setHeader('Set-Cookie',`sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${process.env.COOKIE_SECURE==='1'?'; Secure':''}`);return json(res,200,{name,game:a.game})}
if(p==='/api/logout'&&req.method==='POST'){sessions.delete(cookies(req).sid);res.setHeader('Set-Cookie','sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');return json(res,200,{ok:true})}
if(p==='/api/me'){const name=auth(req);if(!name)return json(res,401,{error:'로그인이 필요합니다'});const a=await getAccount(name);return a?json(res,200,{name,game:a.game}):json(res,401,{error:'계정이 없습니다'})}
if(p==='/api/online'){const name=auth(req);if(!name)return json(res,401,{error:'로그인이 필요합니다'});for(const [k,t] of online)if(Date.now()-t>45000)online.delete(k);return json(res,200,{count:online.size,players:[...online.keys()].slice(0,30)})}
if(p==='/api/save'&&req.method==='POST'){const name=auth(req);if(!name)return json(res,401,{error:'로그인이 필요합니다'});const b=await body(req);if(!b.game||typeof b.game!=='object')return json(res,400,{error:'잘못된 저장 데이터'});const g=b.game;if(JSON.stringify(g).length>200000)return json(res,413,{error:'저장 데이터가 너무 큽니다'});if(!await saveGame(name,{...g,lastSeen:Date.now()}))return json(res,404,{error:'계정이 없습니다'});return json(res,200,{ok:true})}
if(req.method!=='GET')return json(res,405,{error:'허용되지 않은 요청'});
const file=path.resolve(ROOT,'public','.'+decodeURIComponent(p==='/'?'/index.html':p));if(!file.startsWith(path.join(ROOT,'public')+path.sep))return json(res,403,{error:'금지'});fs.readFile(file,(err,data)=>{if(err)return json(res,404,{error:'파일 없음'});res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-cache'});res.end(data)})
}catch(e){console.error(e);if(!res.headersSent)json(res,500,{error:'서버 오류'})}});
initialize().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log(`별빛 원정대 http://localhost:${PORT} (${USE_PG?'PostgreSQL':'LOCAL TEST ONLY'})`))).catch(e=>{console.error('Database initialization failed',e);process.exit(1)});
