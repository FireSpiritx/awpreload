// Kick -> Overlay köprüsü
// -----------------------
// Ne yapar:
//  1) Kick ile OAuth (PKCE) bağlantısı kurar, tek seferlik.
//  2) Kick'in resmi API'sine "abone oldu / hediye abone" eventlerini
//     senin webhook adresine göndermesini söyler.
//  3) Kick'ten gelen her webhook'u, tarayıcıdaki overlay'e WebSocket
//     üzerinden anında iletir -> overlay addSubscriber(isim) çağırır.
//
// Gereksinim: Node.js 18+ (global fetch dahil)

require('dotenv').config();
const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const path = require('path');

const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,        // örn: http://localhost:8787/callback
  BROADCASTER_USER_ID,  // kendi Kick kullanıcı numaran (bkz. adım rehberi)
  WEBHOOK_PUBLIC_URL,   // örn: https://xxxx.ngrok-free.app/webhook/GIZLI_ANAHTAR
  WEBHOOK_SECRET,       // webhook url'sinin sonundaki gizli parça
  PORT = 8787,
} = process.env;

// Eksik/yanlış yazılmış değişken varsa hemen başlangıçta net şekilde söyle
const REQUIRED = { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, BROADCASTER_USER_ID, WEBHOOK_SECRET };
const missing = Object.entries(REQUIRED).filter(([, v]) => !v).map(([k]) => k);
if (missing.length) {
  console.error('EKSİK ORTAM DEĞİŞKENİ(LERİ): ' + missing.join(', '));
  console.error('Railway > Variables sekmesinde bu isimlerin TAM OLARAK böyle yazıldığından emin ol, sonra yeniden deploy et.');
}

const app = express();
app.use(express.json());

let token = null; // { access_token, refresh_token, expires_at }
let pendingVerifier = null;

// ---------- 1) OAuth (PKCE) ----------
function base64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

app.get('/auth', (req, res) => {
  if (!CLIENT_ID || !REDIRECT_URI) {
    return res.status(500).send(
      'CLIENT_ID veya REDIRECT_URI ayarlanmamış. Railway > Variables sekmesini kontrol et. Eksikler: ' +
      [!CLIENT_ID && 'CLIENT_ID', !REDIRECT_URI && 'REDIRECT_URI'].filter(Boolean).join(', ')
    );
  }
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  pendingVerifier = verifier;

  const url = new URL('https://id.kick.com/oauth/authorize');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'events:subscribe channel:read user:read');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', 'kick-bridge');
  res.redirect(url.toString());
});

app.get('/callback', async (req, res) => {
  try {
    const { code, error, error_description } = req.query;
    if (error) {
      return res.status(400).send('Kick izin ekranından hata döndü: ' + error + ' - ' + (error_description || ''));
    }
    if (!code) {
      return res.status(400).send('URL içinde "code" parametresi yok. Kick izin ekranını tam onaylamadan mı geldin?');
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: pendingVerifier,
    });
    const r = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    const raw = await r.text();
    let data;
    try { data = JSON.parse(raw); } catch { data = null; }

    if (!r.ok || !data || !data.access_token) {
      console.error('Kick token endpoint cevabı - status:', r.status, 'body:', raw);
      return res.status(500).send(
        'Token alınamadı. HTTP durumu: ' + r.status + '<br>Kick\'in ham cevabı: <pre>' +
        (raw || '(boş cevap)') + '</pre>' +
        'Deploy Logs\'ta da aynısı yazıyor. Muhtemel sebep: CLIENT_SECRET yanlış, ya da REDIRECT_URI Kick uygulama ayarındakiyle birebir aynı değil.'
      );
    }

    token = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + (data.expires_in || 3600) * 1000,
    };
    res.send('Kick hesabı bağlandı, bu sekmeyi kapatabilirsin. Şimdi /subscribe adresine gidip event aboneliğini başlat.');
  } catch (err) {
    console.error(err);
    res.status(500).send('Token alınamadı: ' + err.message);
  }
});

// ---------- 2) Kick'e "şu eventleri şu webhook'a gönder" de ----------
app.get('/subscribe', async (req, res) => {
  if (!token) return res.status(400).send('Önce /auth ile giriş yap.');
  try {
    const r = await fetch('https://api.kick.com/public/v1/events/subscriptions', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + token.access_token,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        events: [
          { name: 'channel.subscription.new', version: 1 },
          { name: 'channel.subscription.renewal', version: 1 },
          { name: 'channel.subscription.gifts', version: 1 },
        ],
        method: 'webhook',
        broadcaster_user_id: Number(BROADCASTER_USER_ID),
      }),
    });
    if (r.status === 204) return res.send('Abonelik events tetikleyicisi kuruldu. Artık gerçek abonelerde webhook tetiklenecek.');
    const data = await r.json().catch(() => ({}));
    res.status(r.status).json(data);
  } catch (err) {
    console.error(err);
    res.status(500).send('Abonelik kurulamadı: ' + err.message);
  }
});

// ---------- 3) Kick'ten gelen webhook'u overlay'e ilet ----------
app.post('/webhook/:secret', (req, res) => {
  if (req.params.secret !== WEBHOOK_SECRET) return res.status(403).end();

  const eventType = req.header('Kick-Event-Type') || req.body?.event || '';
  const data = req.body || {};

  console.log('Webhook geldi:', eventType, JSON.stringify(data));

  // Kick'in gönderdiği alan adı event tipine göre değişebiliyor,
  // birden fazla olası alanı deniyoruz. Konsolda ham veriyi görüp
  // gerekirse burayı kendi payload'ına göre güncelle.
  let name =
    data?.subscriber?.username ||
    data?.gifter?.username ||
    data?.gifted_usernames?.[0] ||
    data?.user?.username ||
    'Anonim';

  broadcast({ type: 'sub', name });
  res.status(200).end();
});

// ---------- WebSocket: overlay buraya bağlanır ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

function broadcast(payload) {
  const msg = JSON.stringify(payload);
  wss.clients.forEach((c) => {
    if (c.readyState === 1) c.send(msg);
  });
}

// Overlay dosyasını da bu sunucudan servis edelim (OBS'e http:// vermek
// file:// vermekten daha sorunsuz çalışır)
app.use('/overlay', express.static(path.join(__dirname, 'overlay')));

// Test için: tarayıcıdan/terminalden manuel tetikleme
app.get('/test/:name', (req, res) => {
  broadcast({ type: 'sub', name: req.params.name });
  res.send('gönderildi: ' + req.params.name);
});

server.listen(PORT, () => {
  console.log(`Kick köprüsü çalışıyor: http://localhost:${PORT}`);
  console.log(`1) http://localhost:${PORT}/auth  -> Kick hesabınla giriş yap`);
  console.log(`2) http://localhost:${PORT}/subscribe -> event aboneliğini kur`);
  console.log(`3) OBS Browser Source -> http://localhost:${PORT}/overlay?ws=ws://localhost:${PORT}/ws&demo=0`);
});
