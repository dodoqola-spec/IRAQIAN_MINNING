import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import argon2 from 'argon2';
import {Pool} from 'pg';
import {createPublicClient,http,parseAbi,getAddress} from 'viem';
import {polygon,bsc} from 'viem/chains';
import {z} from 'zod';

const app=express();
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='true'?{rejectUnauthorized:false}:undefined});
app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'20kb'})); app.use(cookieParser()); app.use(express.static('public'));
const authLimiter=rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true});
const apiLimiter=rateLimit({windowMs:60*1000,limit:120,standardHeaders:true});
const transferAbi=parseAbi(['event Transfer(address indexed from,address indexed to,uint256 value)']);
const decimalsAbi=parseAbi(['function decimals() view returns (uint8)']);
const cfg={
 wallet:getAddress(process.env.DEPOSIT_WALLET),
 polygon:{chain:polygon,rpc:process.env.POLYGON_RPC_URL,token:getAddress(process.env.POLYGON_USDT_CONTRACT),confirmations:+(process.env.POLYGON_CONFIRMATIONS||20)},
 bsc:{chain:bsc,rpc:process.env.BSC_RPC_URL,token:getAddress(process.env.BSC_USDT_CONTRACT),confirmations:+(process.env.BSC_CONFIRMATIONS||15)}
};
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
async function session(uid,res){
 const raw=crypto.randomBytes(32).toString('hex');
 await pool.query(`INSERT INTO sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '7 days')`,[uid,sha(raw)]);
 res.cookie('sid',raw,{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:604800000,path:'/'});
}
async function auth(req,res,next){
 const raw=req.cookies.sid;if(!raw)return res.status(401).json({error:'غير مسجل الدخول'});
 const {rows}=await pool.query(`SELECT u.id,u.email,u.role,u.balance FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()`,[sha(raw)]);
 if(!rows[0])return res.status(401).json({error:'الجلسة منتهية'});req.user=rows[0];next();
}
function admin(req,res,next){if(req.user?.role!=='admin')return res.status(403).json({error:'صلاحيات المدير مطلوبة'});next()}
function addr(a){try{return getAddress(a)}catch{return null}}
function tokenAmount(raw,decimals){return Number(raw)/10**decimals}
async function chainClient(network){const n=cfg[network];return createPublicClient({chain:n.chain,transport:http(n.rpc)})}
async function findUsdtTransfer(network,txHash){
 const n=cfg[network], c=await chainClient(network);
 const r=await c.getTransactionReceipt({hash:txHash});
 if(r.status!=='success')throw Error('المعاملة فاشلة');
 const latest=await c.getBlockNumber(), conf=Number(latest-r.blockNumber)+1;
 if(conf<n.confirmations)throw Error(`التأكيدات غير كافية: ${conf}/${n.confirmations}`);
 const decimals=Number(await c.readContract({address:n.token,abi:decimalsAbi,functionName:'decimals'}));
 const logs=await c.getLogs({address:n.token,event:transferAbi[0],fromBlock:r.blockNumber,toBlock:r.blockNumber});
 const transfers=[];
 for(const l of logs){
  if(l.transactionHash!==txHash||!l.args?.to)continue;
  transfers.push({from:getAddress(l.args.from),to:getAddress(l.args.to),raw:l.args.value??0n,amount:tokenAmount(l.args.value??0n,decimals)});
 }
 return {receipt:r,confirmations:conf,decimals,transfers};
}
async function verifyDeposit(network,txHash){
 const x=await findUsdtTransfer(network,txHash);
 const t=x.transfers.filter(v=>v.to===cfg.wallet&&v.amount>0);
 if(!t.length)throw Error('لا يوجد تحويل USDT إلى محفظة المنصة');
 const amount=t.reduce((s,v)=>s+v.amount,0);
 if(!Number.isFinite(amount)||amount<=0)throw Error('قيمة غير صالحة');
 return {amount,decimals:x.decimals};
}
async function verifyWithdrawal(network,txHash,address,expectedAmount){
 const x=await findUsdtTransfer(network,txHash), target=getAddress(address);
 const t=x.transfers.filter(v=>v.to===target&&v.amount>=expectedAmount-1e-9);
 if(!t.length)throw Error('TXID لا يثبت تحويل المبلغ المطلوب إلى عنوان المستلم');
 return {amount:t.reduce((s,v)=>s+v.amount,0),decimals:x.decimals};
}

app.post('/api/register',authLimiter,async(req,res)=>{
 const p=z.object({email:z.string().email(),password:z.string().min(10).max(200)}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'كلمة المرور يجب أن تكون 10 أحرف على الأقل'});
 try{const h=await argon2.hash(p.data.password);const {rows}=await pool.query(`INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,role,balance`,[p.data.email.toLowerCase(),h]);await session(rows[0].id,res);res.json({user:rows[0]})}
 catch(e){res.status(e.code==='23505'?409:500).json({error:e.code==='23505'?'البريد مستخدم مسبقاً':'تعذر إنشاء الحساب'})}
});
app.post('/api/login',authLimiter,async(req,res)=>{
 const p=z.object({email:z.string().email(),password:z.string().min(1)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'بيانات غير صالحة'});
 const {rows}=await pool.query('SELECT * FROM users WHERE email=$1',[p.data.email.toLowerCase()]);
 if(!rows[0]||!(await argon2.verify(rows[0].password_hash,p.data.password)))return res.status(401).json({error:'البريد أو كلمة المرور غير صحيحة'});
 await session(rows[0].id,res);res.json({user:{id:rows[0].id,email:rows[0].email,role:rows[0].role,balance:rows[0].balance}});
});
app.post('/api/logout',auth,async(req,res)=>{await pool.query('DELETE FROM sessions WHERE user_id=$1',[req.user.id]);res.clearCookie('sid');res.json({ok:true})});
app.get('/api/me',auth,async(req,res)=>{const {rows}=await pool.query('SELECT id,email,role,balance FROM users WHERE id=$1',[req.user.id]);res.json({user:rows[0]})});
app.get('/api/plans',async(req,res)=>{const {rows}=await pool.query('SELECT id,name,price,duration_days FROM plans WHERE active ORDER BY price');res.json({plans:rows})});
app.get('/api/my-subscriptions',auth,async(req,res)=>{const {rows}=await pool.query(`SELECT s.*,p.name FROM subscriptions s JOIN plans p ON p.id=s.plan_id WHERE s.user_id=$1 ORDER BY s.created_at DESC LIMIT 20`,[req.user.id]);res.json({subscriptions:rows})});

app.post('/api/subscriptions',apiLimiter,auth,async(req,res)=>{
 const p=z.object({planId:z.coerce.number().int().positive()}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'الخطة غير صالحة'});
 const c=await pool.connect();try{await c.query('BEGIN');
  const pl=await c.query('SELECT * FROM plans WHERE id=$1 AND active FOR UPDATE',[p.data.planId]);if(!pl.rows[0]){await c.query('ROLLBACK');return res.status(404).json({error:'الخطة غير موجودة'})}
  const price=Number(pl.rows[0].price);const u=await c.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE',[req.user.id]);
  if(Number(u.rows[0].balance)<price){await c.query('ROLLBACK');return res.status(400).json({error:'الرصيد غير كافٍ'})}
  const s=await c.query(`INSERT INTO subscriptions(user_id,plan_id,amount,ends_at) VALUES($1,$2,$3,now()+($4||' days')::interval) RETURNING *`,[req.user.id,p.data.planId,price,pl.rows[0].duration_days]);
  await c.query('UPDATE users SET balance=balance-$1 WHERE id=$2',[price,req.user.id]);
  await c.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)',[req.user.id,'subscription_purchased',JSON.stringify({planId:p.data.planId,amount:price})]);
  await c.query('COMMIT');res.json({subscription:s.rows[0]});
 }catch(e){await c.query('ROLLBACK');res.status(500).json({error:'تعذر شراء الاشتراك'})}finally{c.release()}
});

app.post('/api/deposits',apiLimiter,auth,async(req,res)=>{
 const p=z.object({network:z.enum(['polygon','bsc']),txHash:z.string().regex(/^0x[a-fA-F0-9]{64}$/)}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'TXID أو الشبكة غير صالحة'});
 try{
  const exists=await pool.query('SELECT id,status FROM deposits WHERE network=$1 AND tx_hash=$2',[p.data.network,p.data.txHash]);
  if(exists.rows[0])return res.status(409).json({error:'TXID مستخدم مسبقاً'});
  const {amount}=await verifyDeposit(p.data.network,p.data.txHash);
  const d=await pool.query(`INSERT INTO deposits(user_id,network,tx_hash,amount,status,verified_at) VALUES($1,$2,$3,$4,'pending',now()) RETURNING id,amount,status`,[req.user.id,p.data.network,p.data.txHash,amount]);
  await pool.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)',[req.user.id,'deposit_verified_pending',JSON.stringify({depositId:d.rows[0].id,network:p.data.network,txHash:p.data.txHash,amount})]);
  res.json({deposit:d.rows[0],message:'تم التحقق من المعاملة ووضعها بانتظار موافقة الإدارة'});
 }catch(e){res.status(400).json({error:e.message||'تعذر التحقق من الإيداع'})}
});
app.get('/api/my-deposits',auth,async(req,res)=>{const {rows}=await pool.query('SELECT id,network,tx_hash,amount,status,created_at,verified_at FROM deposits WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.user.id]);res.json({deposits:rows})});

app.post('/api/withdrawals',apiLimiter,auth,async(req,res)=>{
 const p=z.object({network:z.enum(['polygon','bsc']),address:z.string(),amount:z.number().positive().max(1000000)}).safeParse(req.body);
 if(!p.success)return res.status(400).json({error:'بيانات السحب غير صالحة'});const a=addr(p.data.address);if(!a)return res.status(400).json({error:'العنوان غير صالح'});
 const c=await pool.connect();try{await c.query('BEGIN');const u=await c.query('SELECT balance FROM users WHERE id=$1 FOR UPDATE',[req.user.id]);
 if(Number(u.rows[0].balance)<p.data.amount){await c.query('ROLLBACK');return res.status(400).json({error:'الرصيد غير كافٍ'})}
 await c.query('UPDATE users SET balance=balance-$1 WHERE id=$2',[p.data.amount,req.user.id]);
 const w=await c.query(`INSERT INTO withdrawals(user_id,network,address,amount) VALUES($1,$2,$3,$4) RETURNING *`,[req.user.id,p.data.network,a,p.data.amount]);
 await c.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)',[req.user.id,'withdrawal_created',JSON.stringify({id:w.rows[0].id})]);
 await c.query('COMMIT');res.json({withdrawal:w.rows[0]})}catch(e){await c.query('ROLLBACK');res.status(500).json({error:'تعذر إنشاء السحب'})}finally{c.release()}
});
app.get('/api/my-withdrawals',auth,async(req,res)=>{const {rows}=await pool.query('SELECT * FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50',[req.user.id]);res.json({withdrawals:rows})});

app.get('/api/admin/stats',auth,admin,async(req,res)=>{
 const q=await Promise.all([pool.query('SELECT count(*)::int n FROM users'),pool.query(`SELECT coalesce(sum(amount),0) n FROM deposits WHERE status='approved'`),pool.query(`SELECT coalesce(sum(amount),0) n FROM withdrawals WHERE status='pending'`),pool.query(`SELECT count(*)::int n FROM withdrawals WHERE status='pending'`),pool.query(`SELECT count(*)::int n FROM deposits WHERE status='pending'`) ]);
 res.json({users:q[0].rows[0].n,deposits:q[1].rows[0].n,pending:q[2].rows[0].n,pendingCount:q[3].rows[0].n,pendingDeposits:q[4].rows[0].n})
});
app.get('/api/admin/deposits',auth,admin,async(req,res)=>{const {rows}=await pool.query(`SELECT d.*,u.email FROM deposits d JOIN users u ON u.id=d.user_id WHERE d.status='pending' ORDER BY d.created_at ASC LIMIT 200`);res.json({deposits:rows})});
app.post('/api/admin/deposits/:id/approve',auth,admin,async(req,res)=>{
 const c=await pool.connect();try{await c.query('BEGIN');const d=await c.query(`SELECT * FROM deposits WHERE id=$1 FOR UPDATE`,[req.params.id]);
 if(!d.rows[0]||d.rows[0].status!=='pending'){await c.query('ROLLBACK');return res.status(409).json({error:'الإيداع غير متاح'})}
 await c.query(`UPDATE deposits SET status='approved',verified_at=coalesce(verified_at,now()) WHERE id=$1`,[req.params.id]);
 await c.query('UPDATE users SET balance=balance+$1 WHERE id=$2',[d.rows[0].amount,d.rows[0].user_id]);
 await c.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)',[req.user.id,'deposit_approved',JSON.stringify({depositId:req.params.id,amount:d.rows[0].amount})]);
 await c.query('COMMIT');res.json({ok:true})}catch(e){await c.query('ROLLBACK');res.status(500).json({error:'تعذر اعتماد الإيداع'})}finally{c.release()}
});
app.post('/api/admin/deposits/:id/reject',auth,admin,async(req,res)=>{const r=await pool.query(`UPDATE deposits SET status='rejected' WHERE id=$1 AND status='pending' RETURNING id`,[req.params.id]);if(!r.rows[0])return res.status(409).json({error:'الإيداع غير متاح'});await pool.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)',[req.user.id,'deposit_rejected',JSON.stringify({depositId:req.params.id})]);res.json({ok:true})});
app.get('/api/admin/withdrawals',auth,admin,async(req,res)=>{const {rows}=await pool.query(`SELECT w.*,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 200`);res.json({withdrawals:rows})});
app.post('/api/admin/withdrawals/:id/pay',auth,admin,async(req,res)=>{
 const p=z.object({txHash:z.string().regex(/^0x[a-fA-F0-9]{64}$/)}).safeParse(req.body);if(!p.success)return res.status(400).json({error:'TXID غير صالح'});
 const c=await pool.connect();try{await c.query('BEGIN');const w=await c.query(`SELECT w.*,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id WHERE w.id=$1 FOR UPDATE`,[req.params.id]);
 if(!w.rows[0]){await c.query('ROLLBACK');return res.status(404).json({error:'الطلب غير موجود'})}
 if(w.rows[0].status!=='pending'){await c.query('ROLLBACK');return res.status(409).json({error:'الطلب ليس معلقاً'})}
 const duplicate=await c.query('SELECT id FROM withdrawals WHERE tx_hash=$1',[p.data.txHash]);if(duplicate.rows[0]){await c.query('ROLLBACK');return res.status(409).json({error:'TXID مستخدم مسبقاً'})}
 await verifyWithdrawal(w.rows[0].network,p.data.txHash,w.rows[0].address,Number(w.rows[0].amount));
 await c.query(`UPDATE withdrawals SET status='paid',tx_hash=$1,paid_at=now() WHERE id=$2`,[p.data.txHash,req.params.id]);
 await c.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)',[req.user.id,'withdrawal_paid',JSON.stringify({withdrawalId:req.params.id,txHash:p.data.txHash})]);
 await c.query('COMMIT');res.json({ok:true})}catch(e){await c.query('ROLLBACK');res.status(400).json({error:e.message||'تعذر تسجيل الدفع'})}finally{c.release()}
});
app.post('/api/admin/withdrawals/:id/reject',auth,admin,async(req,res)=>{
 const c=await pool.connect();try{await c.query('BEGIN');const w=await c.query(`SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE`,[req.params.id]);
 if(!w.rows[0]||w.rows[0].status!=='pending'){await c.query('ROLLBACK');return res.status(409).json({error:'الطلب غير متاح'})}
 await c.query(`UPDATE users SET balance=balance+$1 WHERE id=$2`,[w.rows[0].amount,w.rows[0].user_id]);await c.query(`UPDATE withdrawals SET status='rejected' WHERE id=$1`,[req.params.id]);
 await c.query('INSERT INTO audit_logs(user_id,action,metadata) VALUES($1,$2,$3)',[req.user.id,'withdrawal_rejected',JSON.stringify({withdrawalId:req.params.id})]);await c.query('COMMIT');res.json({ok:true})}catch(e){await c.query('ROLLBACK');res.status(500).json({error:'تعذر رفض الطلب'})}finally{c.release()}
});

async function bootstrap(){if(!process.env.ADMIN_EMAIL||!process.env.ADMIN_PASSWORD)return;const q=await pool.query('SELECT id FROM users WHERE email=$1',[process.env.ADMIN_EMAIL.toLowerCase()]);if(!q.rows[0]){const h=await argon2.hash(process.env.ADMIN_PASSWORD);await pool.query(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin')`,[process.env.ADMIN_EMAIL.toLowerCase(),h]);console.log('Admin created; use a strong password.')}}
app.get('/health',(req,res)=>res.json({ok:true}));
const port=+(process.env.PORT||3000);app.listen(port,async()=>{await bootstrap();console.log(`IRAQIAN MINNING on ${port}`)});
