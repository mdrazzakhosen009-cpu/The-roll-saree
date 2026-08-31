const express = require('express');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { createClient } = require('@libsql/client');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_IMAGE_BYTES = 4 * 1024 * 1024;

function env(name) {
  return String(process.env[name] || '').trim();
}
if (!env('TURSO_DATABASE_URL') || !env('TURSO_AUTH_TOKEN')) {
  console.error('Missing TURSO_DATABASE_URL or TURSO_AUTH_TOKEN. Add both in Render Environment Variables.');
  process.exit(1);
}
if (!/^libsql:\/\//.test(env('TURSO_DATABASE_URL')) && !/^https:\/\//.test(env('TURSO_DATABASE_URL'))) {
  console.error('TURSO_DATABASE_URL must be a libsql:// or https:// Turso URL.');
  process.exit(1);
}

const db = createClient({ url: env('TURSO_DATABASE_URL'), authToken: env('TURSO_AUTH_TOKEN') });
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_IMAGE_BYTES } });
const sessions = new Map();

app.use(express.json({ limit: '12mb' }));
app.use(express.urlencoded({ extended: true, limit: '12mb' }));

const now = () => new Date().toISOString();
const sha256 = value => crypto.createHash('sha256').update(String(value)).digest('hex');
const token = () => crypto.randomBytes(32).toString('hex');
const esc = value => String(value ?? '');

async function exec(sql, args = []) { return db.execute({ sql, args }); }
async function one(sql, args = []) { const r = await exec(sql, args); return r.rows[0] || null; }
async function many(sql, args = []) { const r = await exec(sql, args); return r.rows; }

async function initDatabase() {
  await exec(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await exec(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL DEFAULT 0,
    old_price REAL NOT NULL DEFAULT 0,
    category TEXT NOT NULL DEFAULT 'Saree',
    tags TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    image TEXT NOT NULL DEFAULT '',
    featured INTEGER NOT NULL DEFAULT 0,
    is_new INTEGER NOT NULL DEFAULT 1,
    stock INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await exec(`CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    whatsapp TEXT NOT NULL DEFAULT '',
    messenger TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await exec(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_code TEXT UNIQUE NOT NULL,
    customer_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    items_json TEXT NOT NULL,
    subtotal REAL NOT NULL,
    delivery_fee REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL,
    payment_method TEXT NOT NULL DEFAULT 'COD',
    transaction_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
  await exec(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);

  const admin = await one('SELECT id FROM admins WHERE id=1');
  if (!admin) {
    const initial = env('ADMIN_PASSWORD');
    if (!initial) throw new Error('ADMIN_PASSWORD is required on first startup.');
    await exec('INSERT INTO admins(id,password_hash,created_at,updated_at) VALUES(1,?,?,?)', [sha256(initial), now(), now()]);
  }

  const defaults = {
    store_name: 'SAREE',
    store_tagline: 'Premium Saree Collection',
    store_info: 'Premium sarees and selected fashion collections.',
    delivery_time: 'Inside Dhaka: 1–2 days. Outside Dhaka: 2–4 days.',
    delivery_fee: '80',
    bkash_number: '',
    nagad_number: '',
    rocket_number: '',
    cod_enabled: 'true',
    logo: '',
    theme: 'luxury',
    chatbot_delivery: 'Our delivery usually takes 1–2 days inside Dhaka and 2–4 days outside Dhaka.',
    chatbot_store: 'We sell premium sarees and selected fashion collections.',
    chatbot_order: 'I can take your order here. Tell me which saree you want and the quantity.'
  };
  for (const [key, value] of Object.entries(defaults)) {
    if (!await one('SELECT key FROM settings WHERE key=?', [key])) {
      await exec('INSERT INTO settings(key,value,updated_at) VALUES(?,?,?)', [key, value, now()]);
    }
  }
}

async function settings() {
  const rows = await many('SELECT key,value FROM settings');
  return Object.fromEntries(rows.map(r => [r.key, r.value]));
}

function requireAdmin(req, res, next) {
  const raw = String(req.headers.authorization || '');
  const t = raw.replace(/^Bearer\s+/i, '').trim();
  if (!t || !sessions.has(t)) return res.status(401).json({ error: 'Admin session expired. Please login again.' });
  next();
}

function imageData(file) {
  if (!file || !/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) throw new Error('Only JPG, PNG, WEBP or GIF images are allowed.');
  return `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
}

app.get('/api/health', async (req, res) => {
  try { await one('SELECT 1 AS ok'); res.json({ ok: true, database: 'turso' }); }
  catch (e) { res.status(500).json({ ok: false, error: 'Turso connection failed' }); }
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const a = await one('SELECT password_hash FROM admins WHERE id=1');
    if (!a || sha256(req.body.password || '') !== a.password_hash) return res.status(401).json({ error: 'Invalid admin password.' });
    const t = token();
    sessions.set(t, Date.now());
    res.json({ ok: true, token: t });
  } catch (e) { res.status(500).json({ error: 'Database error during login.' }); }
});
app.post('/api/admin/logout', requireAdmin, (req, res) => { sessions.delete(String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim()); res.json({ ok: true }); });

app.get('/api/settings', async (req, res) => { try { res.json(await settings()); } catch { res.status(500).json({ error: 'Could not load store settings.' }); } });

app.get('/api/products', async (req, res) => {
  try {
    let sql = 'SELECT * FROM products WHERE 1=1', args = [];
    const search = String(req.query.search || '').trim();
    const category = String(req.query.category || '').trim();
    if (search) { sql += ' AND (name LIKE ? OR category LIKE ? OR tags LIKE ? OR description LIKE ?)'; const x = `%${search}%`; args.push(x,x,x,x); }
    if (category) { sql += ' AND category=?'; args.push(category); }
    res.json(await many(sql + ' ORDER BY featured DESC,is_new DESC,id DESC', args));
  } catch { res.status(500).json({ error: 'Could not load products.' }); }
});
app.get('/api/agents', async (req, res) => { try { res.json(await many('SELECT * FROM agents WHERE active=1 ORDER BY id DESC')); } catch { res.status(500).json({ error: 'Could not load agents.' }); } });

async function createOrder(body) {
  const items = Array.isArray(body.items) ? body.items : [];
  if (!body.customer_name || !body.phone || !body.address || !items.length) throw new Error('Customer name, phone, address and at least one product are required.');
  const ids = [...new Set(items.map(x => Number(x.id)).filter(Number.isInteger))];
  if (!ids.length) throw new Error('No valid product selected.');
  const products = await many(`SELECT * FROM products WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
  const map = new Map(products.map(p => [Number(p.id), p]));
  const clean = items.map(x => {
    const p = map.get(Number(x.id));
    if (!p) return null;
    const qty = Math.max(1, Math.min(99, Number(x.qty || 1)));
    return { id: Number(p.id), name: p.name, price: Number(p.price), qty, image: p.image || '' };
  }).filter(Boolean);
  if (!clean.length) throw new Error('Selected product is no longer available.');
  const cfg = await settings();
  const method = String(body.payment_method || 'COD');
  if (!['COD','bKash','Nagad','Rocket'].includes(method)) throw new Error('Invalid payment method.');
  if (method === 'COD' && cfg.cod_enabled !== 'true') throw new Error('Cash on Delivery is currently disabled.');
  if (method !== 'COD' && !String(body.transaction_id || '').trim()) throw new Error('Transaction ID is required for online payment.');
  const subtotal = clean.reduce((sum, x) => sum + x.price * x.qty, 0);
  const delivery = Number(cfg.delivery_fee || 0);
  const total = subtotal + delivery;
  const next = Number((await one('SELECT COALESCE(MAX(id),0)+1 AS n FROM orders')).n);
  const code = `SAR-${String(next).padStart(6,'0')}`;
  await exec(`INSERT INTO orders(order_code,customer_name,phone,address,items_json,subtotal,delivery_fee,total,payment_method,transaction_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, [code, String(body.customer_name).trim(), String(body.phone).trim(), String(body.address).trim(), JSON.stringify(clean), subtotal, delivery, total, method, String(body.transaction_id || '').trim(), 'Pending', now(), now()]);
  return { order_id: code, total, delivery_fee: delivery };
}

app.post('/api/orders', async (req, res) => { try { res.json({ ok: true, ...(await createOrder(req.body || {})) }); } catch (e) { res.status(400).json({ error: e.message }); } });
app.get('/api/orders/:code', async (req, res) => { try { const o = await one('SELECT * FROM orders WHERE order_code=?', [String(req.params.code).toUpperCase()]); if (!o) return res.status(404).json({ error: 'Order not found.' }); o.items = JSON.parse(o.items_json); delete o.items_json; res.json(o); } catch { res.status(500).json({ error: 'Could not load order.' }); } });

app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  try {
    const [orders, products, agents, revenue] = await Promise.all([
      one('SELECT COUNT(*) c FROM orders'), one('SELECT COUNT(*) c FROM products'), one('SELECT COUNT(*) c FROM agents'), one("SELECT COALESCE(SUM(total),0) revenue FROM orders WHERE status!='Cancelled'")
    ]);
    res.json({ orders: Number(orders.c), products: Number(products.c), agents: Number(agents.c), revenue: Number(revenue.revenue) });
  } catch { res.status(500).json({ error: 'Could not load dashboard.' }); }
});
app.get('/api/admin/orders', requireAdmin, async (req, res) => { try { res.json(await many('SELECT * FROM orders ORDER BY id DESC')); } catch { res.status(500).json({ error: 'Could not load orders.' }); } });
app.patch('/api/admin/orders/:id', requireAdmin, async (req, res) => { try { await exec('UPDATE orders SET status=?,updated_at=? WHERE id=?', [String(req.body.status || 'Pending'), now(), Number(req.params.id)]); res.json({ ok:true }); } catch { res.status(500).json({ error:'Could not update order.' }); } });

app.get('/api/admin/products', requireAdmin, async (req,res)=>{ try{res.json(await many('SELECT * FROM products ORDER BY id DESC'));}catch{res.status(500).json({error:'Could not load products.'});} });
app.post('/api/admin/products', requireAdmin, upload.single('image'), async (req,res)=>{
  try { const b=req.body; if(!String(b.name||'').trim()) throw Error('Product name is required.'); const img=req.file?imageData(req.file):String(b.image||''); await exec(`INSERT INTO products(name,price,old_price,category,tags,description,image,featured,is_new,stock,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,[String(b.name).trim(),Number(b.price)||0,Number(b.old_price)||0,String(b.category||'Saree'),String(b.tags||''),String(b.description||''),img,b.featured==='true'?1:0,b.is_new==='false'?0:1,Number(b.stock)||0,now(),now()]); res.json({ok:true}); } catch(e){res.status(400).json({error:e.message});}
});
app.put('/api/admin/products/:id', requireAdmin, upload.single('image'), async (req,res)=>{
  try { const old=await one('SELECT image FROM products WHERE id=?',[Number(req.params.id)]); if(!old) return res.status(404).json({error:'Product not found.'}); const b=req.body; const img=req.file?imageData(req.file):String(b.image||old.image||''); await exec(`UPDATE products SET name=?,price=?,old_price=?,category=?,tags=?,description=?,image=?,featured=?,is_new=?,stock=?,updated_at=? WHERE id=?`,[String(b.name||'').trim(),Number(b.price)||0,Number(b.old_price)||0,String(b.category||'Saree'),String(b.tags||''),String(b.description||''),img,b.featured==='true'?1:0,b.is_new==='false'?0:1,Number(b.stock)||0,now(),Number(req.params.id)]); res.json({ok:true}); } catch(e){res.status(400).json({error:e.message});}
});
app.delete('/api/admin/products/:id', requireAdmin, async (req,res)=>{try{await exec('DELETE FROM products WHERE id=?',[Number(req.params.id)]);res.json({ok:true});}catch{res.status(500).json({error:'Could not delete product.'});}});

app.get('/api/admin/agents', requireAdmin, async(req,res)=>{try{res.json(await many('SELECT * FROM agents ORDER BY id DESC'));}catch{res.status(500).json({error:'Could not load agents.'});}});
app.post('/api/admin/agents', requireAdmin, async(req,res)=>{try{const b=req.body;if(!String(b.name||'').trim())throw Error('Agent name is required.');await exec('INSERT INTO agents(name,phone,whatsapp,messenger,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',[b.name,b.phone||'',b.whatsapp||'',b.messenger||'',b.active===false?0:1,now(),now()]);res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});
app.put('/api/admin/agents/:id', requireAdmin, async(req,res)=>{try{const b=req.body;await exec('UPDATE agents SET name=?,phone=?,whatsapp=?,messenger=?,active=?,updated_at=? WHERE id=?',[b.name,b.phone||'',b.whatsapp||'',b.messenger||'',b.active?1:0,now(),Number(req.params.id)]);res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});
app.delete('/api/admin/agents/:id', requireAdmin, async(req,res)=>{try{await exec('DELETE FROM agents WHERE id=?',[Number(req.params.id)]);res.json({ok:true});}catch{res.status(500).json({error:'Could not delete agent.'});}});

app.put('/api/admin/settings', requireAdmin, async(req,res)=>{try{for(const [k,v] of Object.entries(req.body||{})){if(!/^[a-z_]+$/.test(k))continue;await exec('INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at',[k,String(v),now()]);}res.json({ok:true});}catch{res.status(500).json({error:'Could not save settings.'});}});
app.post('/api/admin/logo', requireAdmin, upload.single('image'), async(req,res)=>{try{const img=imageData(req.file);await exec(`INSERT INTO settings(key,value,updated_at) VALUES('logo',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`,[img,now()]);res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});
app.post('/api/admin/password', requireAdmin, async(req,res)=>{try{const a=await one('SELECT password_hash FROM admins WHERE id=1');const old=String(req.body.old_password||''),n=String(req.body.new_password||'');if(sha256(old)!==a.password_hash)return res.status(401).json({error:'Current password is incorrect.'});if(n.length<6)return res.status(400).json({error:'New password must be at least 6 characters.'});await exec('UPDATE admins SET password_hash=?,updated_at=? WHERE id=1',[sha256(n),now()]);sessions.clear();res.json({ok:true,login_required:true});}catch{res.status(500).json({error:'Could not change password.'});}});

async function groq(messages, vision=false) {
  const key=env('GROQ_API_KEY'); if(!key) throw Error('GROQ_API_KEY is not configured.');
  const model=env('GROQ_MODEL') || (vision ? 'meta-llama/llama-4-scout-17b-16e-instruct' : 'llama-4-scout-17b-16e-instruct');
  const r=await fetch('https://api.groq.com/openai/v1/chat/completions',{method:'POST',headers:{Authorization:`Bearer ${key}`,'Content-Type':'application/json'},body:JSON.stringify({model,temperature:.15,messages})});
  if(!r.ok) throw Error(`Groq API returned ${r.status}.`); const j=await r.json(); return j.choices?.[0]?.message?.content||'';
}

app.post('/api/chat', async(req,res)=>{
  try{
    const cfg=await settings();
    const catalog=await many('SELECT id,name,price,category,tags,description,stock,image FROM products ORDER BY featured DESC,is_new DESC,id DESC');
    const catalogText=catalog.map(p=>`ID=${p.id}|${p.name}|৳${p.price}|${p.category}|stock=${p.stock}|${p.tags}|${p.description}`).join('\n');
    const state=req.body.state||{};
    const system=`You are the SAREE Premium shopping assistant. Answer in the customer's language. Use ONLY the catalog/store facts below; never invent price, stock, payment number or delivery time. You can answer normal questions. If the customer wants to order, collect ONE missing field at a time: product, quantity, customer_name, phone, address, payment_method, transaction_id when online payment is used. After all fields are present, ask for confirmation. Return STRICT JSON only: {"reply":"...","state":{"product_id":number|null,"quantity":number,"customer_name":"","phone":"","address":"","payment_method":"COD|bKash|Nagad|Rocket|","transaction_id":"","confirmed":false}}. For ordinary questions keep confirmed false. Store: ${cfg.store_info}. Delivery: ${cfg.delivery_time}. Payments: bKash=${cfg.bkash_number||'not set'}, Nagad=${cfg.nagad_number||'not set'}, Rocket=${cfg.rocket_number||'not set'}, COD=${cfg.cod_enabled}. Catalog:\n${catalogText}\nCurrent state:${JSON.stringify(state)}`;
    const raw=await groq([{role:'system',content:system},{role:'user',content:String(req.body.message||'')}]);
    let parsed; try{parsed=JSON.parse(raw.replace(/^```json\s*|\s*```$/g,''));}catch{parsed={reply:raw,state};}
    const s={...state,...(parsed.state||{})};
    if(parsed.state?.payment_method && parsed.state.payment_method!=='COD' && !s.transaction_id){s.confirmed=false;}
    res.json({reply:parsed.reply||'How can I help you?',state:s});
  }catch(e){res.status(500).json({error:'AI is temporarily unavailable. Please contact an agent.'});}
});

app.post('/api/chat/confirm-order', async(req,res)=>{try{if(!req.body.confirmed)return res.status(400).json({error:'Order is not confirmed.'});res.json({ok:true,...await createOrder(req.body)});}catch(e){res.status(400).json({error:e.message});}});

app.post('/api/catalog-match', upload.single('image'), async(req,res)=>{
  try{
    const image=imageData(req.file); const products=await many('SELECT id,name,price,category,tags,description,image FROM products WHERE stock>0 ORDER BY featured DESC,id DESC');
    const prompt=[{type:'text',text:`Match this customer image against this SAREE catalog. Return JSON only: {"matches":[{"id":number,"confidence":0-1,"reason":"short"}]}. Catalog:\n${products.map(p=>`ID=${p.id}|${p.name}|${p.category}|${p.tags}|${p.description}`).join('\n')}`},{type:'image_url',image_url:{url:image}}];
    const raw=await groq([{role:'user',content:prompt}],true); let parsed;try{parsed=JSON.parse(raw.replace(/^```json\s*|\s*```$/g,''));}catch{parsed={matches:[]};}
    const valid=(parsed.matches||[]).filter(x=>products.some(p=>Number(p.id)===Number(x.id))).slice(0,5).map(x=>({...x,product:products.find(p=>Number(p.id)===Number(x.id))}));res.json({matches:valid});
  }catch(e){res.status(400).json({error:'Image matching is unavailable right now. Please use product search or contact an agent.'});}
});

app.use('/admin',express.static(path.join(__dirname,'admin')));
app.use(express.static(path.join(__dirname,'public')));
app.get('/admin/*',(req,res)=>res.sendFile(path.join(__dirname,'admin','index.html')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

initDatabase().then(async()=>{await one('SELECT 1');app.listen(PORT,()=>console.log(`SAREE server listening on ${PORT}; Turso connected.`));}).catch(err=>{console.error('Startup failed: Turso connection/schema initialization failed.');console.error(err);process.exit(1);});
