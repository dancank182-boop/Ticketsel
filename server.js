const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const QRCode = require("qrcode");

const app = express();
app.use(express.json({limit:"100kb"}));
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const MPESA_ENV = (process.env.MPESA_ENV || "sandbox").toLowerCase();
const MPESA_BASE = MPESA_ENV === "production"
  ? "https://api.safaricom.co.ke"
  : "https://sandbox.safaricom.co.ke";

const DATA = path.join(__dirname, "data");
const ORDERS = path.join(DATA, "orders.json");
const USERS = path.join(DATA, "users.json");
fs.mkdirSync(DATA, {recursive:true});
if(!fs.existsSync(ORDERS)) fs.writeFileSync(ORDERS, "[]");
if(!fs.existsSync(USERS)) fs.writeFileSync(USERS, "[]");

function readUsers(){ return JSON.parse(fs.readFileSync(USERS,"utf8")); }
function writeUsers(x){ fs.writeFileSync(USERS, JSON.stringify(x,null,2)); }
function publicUser(u){ return {id:u.id,name:u.name,email:u.email,createdAt:u.createdAt}; }
function hashPassword(password, salt=crypto.randomBytes(16).toString("hex")){
  return {salt,hash:crypto.scryptSync(password,salt,64).toString("hex")};
}
function validPassword(password, salt, hash){
  return crypto.scryptSync(password,salt,64).toString("hex")===hash;
}
const sessions=new Map();
function sessionUser(req){ const id=sessions.get(req.headers["x-ticketfy-session"]); return id ? readUsers().find(u=>u.id===id) : null; }

function readOrders(){ return JSON.parse(fs.readFileSync(ORDERS,"utf8")); }
function writeOrders(x){ fs.writeFileSync(ORDERS, JSON.stringify(x,null,2)); }
function normalizePhone(phone){
  const x=String(phone||"").replace(/\\D/g,"");
  if(x.startsWith("254") && x.length===12) return x;
  if(x.startsWith("0") && x.length===10) return "254"+x.slice(1);
  if(x.startsWith("7") && x.length===9) return "254"+x;
  throw new Error("Enter a valid Kenyan M-Pesa number.");
}
function env(name){
  if(!process.env[name]) throw new Error(`Missing ${name}. Add it to .env`);
  return process.env[name];
}
async function getToken(){
  const key=env("MPESA_CONSUMER_KEY"), secret=env("MPESA_CONSUMER_SECRET");
  const auth=Buffer.from(`${key}:${secret}`).toString("base64");
  const r=await fetch(`${MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials`,{
    headers:{Authorization:`Basic ${auth}`}
  });
  const d=await r.json();
  if(!r.ok || !d.access_token) throw new Error(d.errorMessage||"Could not authenticate with Daraja.");
  return d.access_token;
}
function timestamp(){
  const d=new Date();
  const pad=n=>String(n).padStart(2,"0");
  return d.getFullYear()+pad(d.getMonth()+1)+pad(d.getDate())+pad(d.getHours())+pad(d.getMinutes())+pad(d.getSeconds());
}
function password(ts){
  return Buffer.from(env("MPESA_SHORTCODE")+env("MPESA_PASSKEY")+ts).toString("base64");
}

app.post("/api/auth/signup",(req,res)=>{
  try{
    const {name,email,password}=req.body||{};
    if(!name||!email||!password) return res.status(400).json({error:"Name, email and password are required."});
    if(String(name).trim().length<2) return res.status(400).json({error:"Please enter your full name."});
    const normalized=String(email).trim().toLowerCase();
    if(!/^\\S+@\\S+\\.\\S+$/.test(normalized)) return res.status(400).json({error:"Enter a valid email address."});
    if(String(password).length<6) return res.status(400).json({error:"Password must be at least 6 characters."});
    const users=readUsers();
    if(users.some(u=>u.email===normalized)) return res.status(409).json({error:"An account with that email already exists."});
    const id=crypto.randomUUID(), pw=hashPassword(String(password));
    const user={id,name:String(name).trim(),email:normalized,passwordHash:pw.hash,passwordSalt:pw.salt,createdAt:new Date().toISOString()};
    users.push(user); writeUsers(users);
    const session=crypto.randomBytes(32).toString("hex"); sessions.set(session,id);
    res.json({user:publicUser(user),session});
  }catch(e){res.status(500).json({error:"Could not create account."});}
});

app.post("/api/auth/login",(req,res)=>{
  try{
    const {email,password}=req.body||{}, normalized=String(email||"").trim().toLowerCase();
    const user=readUsers().find(u=>u.email===normalized);
    if(!user||!validPassword(String(password||""),user.passwordSalt,user.passwordHash))
      return res.status(401).json({error:"Incorrect email or password."});
    const session=crypto.randomBytes(32).toString("hex"); sessions.set(session,user.id);
    res.json({user:publicUser(user),session});
  }catch(e){res.status(500).json({error:"Could not sign in."});}
});
app.get("/api/auth/me",(req,res)=>{
  const user=sessionUser(req); res.json({user:user?publicUser(user):null});
});
app.post("/api/auth/logout",(req,res)=>{
  sessions.delete(req.headers["x-ticketfy-session"]); res.json({ok:true});
});

app.post("/api/payments/stkpush", async (req,res)=>{
  try{
    const {eventName,ticketType,quantity,amount,name,phone,email}=req.body;
    if(!eventName||!ticketType||!quantity||!amount||!name||!phone||!email)
      return res.status(400).json({error:"Missing checkout information."});
    const customerPhone=normalizePhone(phone);
    const total=Math.round(Number(amount));
    if(!Number.isInteger(total)||total<1||total>150000) return res.status(400).json({error:"Invalid payment amount."});

    const orderId=crypto.randomUUID();
    const ts=timestamp(), token=await getToken();
    const payload={
      BusinessShortCode:env("MPESA_SHORTCODE"),
      Password:password(ts),
      Timestamp:ts,
      TransactionType:process.env.MPESA_TRANSACTION_TYPE || "CustomerPayBillOnline",
      Amount:total,
      PartyA:customerPhone,
      PartyB:env("MPESA_SHORTCODE"),
      PhoneNumber:customerPhone,
      CallBackURL:`${BASE_URL}/api/mpesa/callback`,
      AccountReference:orderId.slice(0,12),
      TransactionDesc:`Ticketfy ${eventName}`.slice(0,20)
    };
    const r=await fetch(`${MPESA_BASE}/mpesa/stkpush/v1/processrequest`,{
      method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},
      body:JSON.stringify(payload)
    });
    const d=await r.json();
    if(!r.ok || !d.CheckoutRequestID) return res.status(502).json({error:d.errorMessage||d.ResponseDescription||"Daraja rejected the STK request.",daraja:d});

    const orders=readOrders();
    orders.push({
      id:orderId,status:"PENDING",createdAt:new Date().toISOString(),
      eventName,ticketType,quantity:Number(quantity),amount:total,
      customer:{name,email,phone:customerPhone},
      merchantRequestId:d.MerchantRequestID,checkoutRequestId:d.CheckoutRequestID
    });
    writeOrders(orders);
    res.json({orderId,customerMessage:d.CustomerMessage||"Check your phone for the M-Pesa prompt."});
  }catch(e){ console.error(e); res.status(500).json({error:e.message}); }
});

app.post("/api/mpesa/callback",(req,res)=>{
  try{
    const cb=req.body?.Body?.stkCallback;
    if(!cb) return res.status(400).json({ResultCode:1,ResultDesc:"Invalid callback"});
    const orders=readOrders();
    const order=orders.find(o=>o.checkoutRequestId===cb.CheckoutRequestID);
    if(order){
      if(Number(cb.ResultCode)===0){
        const items=Object.fromEntries((cb.CallbackMetadata?.Item||[]).map(x=>[x.Name,x.Value]));
        order.status="PAID";
        order.mpesaReceipt=items.MpesaReceiptNumber || null;
        order.paidAt=new Date().toISOString();
        order.ticketId="TFY-"+crypto.randomBytes(4).toString("hex").toUpperCase();
        order.qrPayload=`TICKETFY|${order.ticketId}|${order.eventName}|${order.amount}`;
      }else{
        order.status=Number(cb.ResultCode)===1032?"CANCELLED":"FAILED";
        order.message=cb.ResultDesc||"Payment was not completed.";
      }
      writeOrders(orders);
    }
    res.json({ResultCode:0,ResultDesc:"Accepted"});
  }catch(e){ console.error(e); res.status(500).json({ResultCode:1,ResultDesc:"Callback error"}); }
});

app.get("/api/orders/:id", async (req,res)=>{
  const order=readOrders().find(o=>o.id===req.params.id);
  if(!order) return res.status(404).json({error:"Order not found"});
  const safe={...order};
  delete safe.merchantRequestId; delete safe.checkoutRequestId;
  if(order.status==="PAID") safe.qrDataUrl=await QRCode.toDataURL(order.qrPayload,{margin:1,width:280});
  res.json(safe);
});

app.get("/api/health",(req,res)=>res.json({ok:true,service:"Ticketfy",environment:MPESA_ENV}));
app.get(/.*/,(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT,()=>console.log(`Ticketfy running on ${BASE_URL}`));
