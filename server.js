// Kick -> Overlay köprüsü
// -----------------------
// Kick OAuth (PKCE) + Webhook + WebSocket Overlay

require('dotenv').config();

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const path = require('path');

const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  BROADCASTER_USER_ID,
  WEBHOOK_PUBLIC_URL,
  WEBHOOK_SECRET,
  PORT = 8787,
} = process.env;

// ---------- Ortam değişkenleri ----------

const REQUIRED = {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  BROADCASTER_USER_ID,
  WEBHOOK_SECRET,
};

const missing = Object.entries(REQUIRED)
  .filter(([, v]) => !v)
  .map(([k]) => k);

if (missing.length) {
  console.error(
    'EKSİK ORTAM DEĞİŞKENİ(LERİ): ' + missing.join(', ')
  );
  console.error(
    'Railway > Variables bölümünü kontrol et.'
  );
}

// ---------- Express ----------

const app = express();

app.use(express.json());

// Token RAM'de tutulur.
// Railway restart olursa tekrar /auth yapılması gerekir.
let token = null;

// ---------- Yardımcı fonksiyonlar ----------

function base64url(buf) {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};

  header.split(';').forEach((part) => {
    const index = part.indexOf('=');

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (key) {
      cookies[key] = decodeURIComponent(value);
    }
  });

  return cookies;
}

function setCookie(res, name, value, options = {}) {
  let cookie = `${name}=${encodeURIComponent(value)}`;

  if (options.maxAge !== undefined) {
    cookie += `; Max-Age=${options.maxAge}`;
  }

  if (options.httpOnly) {
    cookie += '; HttpOnly';
  }

  if (options.secure) {
    cookie += '; Secure';
  }

  if (options.sameSite) {
    cookie += `; SameSite=${options.sameSite}`;
  }

  if (options.path) {
    cookie += `; Path=${options.path}`;
  }

  res.append('Set-Cookie', cookie);
}

// ---------- 1) OAuth / PKCE ----------

app.get('/auth', (req, res) => {
  if (!CLIENT_ID || !REDIRECT_URI) {
    return res.status(500).send(
      'CLIENT_ID veya REDIRECT_URI ayarlanmamış.'
    );
  }

  // PKCE verifier
  const verifier = base64url(
    crypto.randomBytes(32)
  );

  // S256 challenge
  const challenge = base64url(
    crypto
      .createHash('sha256')
      .update(verifier)
      .digest()
  );

  // Rastgele state
  const state = base64url(
    crypto.randomBytes(32)
  );

  // Verifier'ı tarayıcıya HttpOnly cookie olarak kaydet.
  // Böylece callback hangi server instance'ına giderse
  // verifier tekrar alınabilir.
  setCookie(
    res,
    'kick_pkce_verifier',
    verifier,
    {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 600,
      path: '/',
    }
  );

  // State'i de cookie olarak sakla.
  setCookie(
    res,
    'kick_oauth_state',
    state,
    {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 600,
      path: '/',
    }
  );

  const url = new URL(
    'https://id.kick.com/oauth/authorize'
  );

  url.searchParams.set(
    'client_id',
    CLIENT_ID
  );

  url.searchParams.set(
    'redirect_uri',
    REDIRECT_URI
  );

  url.searchParams.set(
    'response_type',
    'code'
  );

  url.searchParams.set(
    'scope',
    'events:subscribe channel:read user:read'
  );

  url.searchParams.set(
    'code_challenge',
    challenge
  );

  url.searchParams.set(
    'code_challenge_method',
    'S256'
  );

  url.searchParams.set(
    'state',
    state
  );

  console.log('OAuth başlatıldı.');
  console.log('PKCE verifier oluşturuldu.');
  console.log('State oluşturuldu.');

  res.redirect(url.toString());
});

// ---------- 2) OAuth callback ----------

app.get('/callback', async (req, res) => {
  try {
    const {
      code,
      state,
      error,
      error_description,
    } = req.query;

    if (error) {
      return res.status(400).send(
        'Kick izin ekranından hata döndü: ' +
        error +
        ' - ' +
        (error_description || '')
      );
    }

    if (!code) {
      return res.status(400).send(
        'URL içinde "code" parametresi yok.'
      );
    }

    const cookies = parseCookies(req);

    const verifier =
      cookies.kick_pkce_verifier;

    const savedState =
      cookies.kick_oauth_state;

    // State kontrolü
    if (!state || !savedState) {
      console.error(
        'OAuth state bulunamadı.'
      );

      return res.status(400).send(
        'OAuth state bulunamadı. /auth adresinden yeniden giriş yap.'
      );
    }

    if (state !== savedState) {
      console.error(
        'OAuth state eşleşmedi.'
      );

      return res.status(400).send(
        'OAuth state eşleşmedi. Güvenlik nedeniyle işlem durduruldu.'
      );
    }

    // PKCE verifier kontrolü
    if (!verifier) {
      console.error(
        'PKCE verifier cookie içinde bulunamadı.'
      );

      return res.status(400).send(
        'PKCE verifier bulunamadı. /auth adresinden yeniden giriş yap.'
      );
    }

    console.log(
      'OAuth callback alındı.'
    );

    console.log(
      'Authorization code alındı.'
    );

    console.log(
      'PKCE verifier bulundu.'
    );

    // Kick token isteği
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code,
      code_verifier: verifier,
    });

    const r = await fetch(
      'https://id.kick.com/oauth/token',
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded',
        },

        body,
      }
    );

    const raw = await r.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      data = null;
    }

    console.log(
      'Kick token endpoint status:',
      r.status
    );

    if (!r.ok || !data || !data.access_token) {
      console.error(
        'Kick token endpoint cevabı:',
        raw
      );

      return res.status(500).send(
        'Token alınamadı.<br>' +
        'Kick HTTP durumu: ' +
        r.status +
        '<br><br>' +
        '<pre>' +
        (raw || '(boş cevap)') +
        '</pre>'
      );
    }

    token = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at:
        Date.now() +
        (data.expires_in || 3600) * 1000,
    };

    // OAuth cookie'lerini temizle
    setCookie(
      res,
      'kick_pkce_verifier',
      '',
      {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        maxAge: 0,
        path: '/',
      }
    );

    setCookie(
      res,
      'kick_oauth_state',
      '',
      {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        maxAge: 0,
        path: '/',
      }
    );

    console.log(
      'Kick hesabı başarıyla bağlandı.'
    );

    res.send(
      'Kick hesabı başarıyla bağlandı.<br><br>' +
      'Bu sekmeyi kapatabilirsin.<br><br>' +
      'Şimdi /subscribe adresine git.'
    );

  } catch (err) {
    console.error(
      'OAuth callback hatası:',
      err
    );

    res.status(500).send(
      'Token alınamadı: ' +
      err.message
    );
  }
});

// ---------- 3) Kick event aboneliği ----------

app.get('/subscribe', async (req, res) => {
  if (!token) {
    return res.status(400).send(
      'Önce /auth ile giriş yap.'
    );
  }

  try {
    const r = await fetch(
      'https://api.kick.com/public/v1/events/subscriptions',
      {
        method: 'POST',

        headers: {
          Authorization:
            'Bearer ' + token.access_token,

          'Content-Type':
            'application/json',
        },

        body: JSON.stringify({
          events: [
            {
              name:
                'channel.subscription.new',
              version: 1,
            },

            {
              name:
                'channel.subscription.renewal',
              version: 1,
            },

            {
              name:
                'channel.subscription.gifts',
              version: 1,
            },
          ],

          method: 'webhook',

          broadcaster_user_id:
            Number(BROADCASTER_USER_ID),
        }),
      }
    );

    const raw = await r.text();

    console.log(
      'Subscribe status:',
      r.status
    );

    if (r.status === 204) {
      return res.send(
        'Abonelik eventleri başarıyla kuruldu.<br><br>' +
        'Yeni abonelik, yenileme ve hediye abonelik eventleri artık webhook adresine gönderilecek.'
      );
    }

    console.error(
      'Subscribe cevabı:',
      raw
    );

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      data = {
        raw,
      };
    }

    res.status(r.status).json(data);

  } catch (err) {
    console.error(err);

    res.status(500).send(
      'Abonelik kurulamadı: ' +
      err.message
    );
  }
});

// ---------- 4) Webhook ----------

app.post(
  '/webhook/:secret',
  (req, res) => {
    if (
      req.params.secret !==
      WEBHOOK_SECRET
    ) {
      console.log(
        'Geçersiz webhook secret.'
      );

      return res.status(403).end();
    }

    const eventType =
      req.header('Kick-Event-Type') ||
      req.body?.event ||
      '';

    const data =
      req.body || {};

    console.log(
      'Webhook geldi:',
      eventType
    );

    console.log(
      'Webhook payload:',
      JSON.stringify(data)
    );

    // Olası isim alanları
    const name =
      data?.subscriber?.username ||
      data?.subscriber?.display_name ||
      data?.gifter?.username ||
      data?.gifter?.display_name ||
      data?.user?.username ||
      data?.user?.display_name ||
      data?.gifted_usernames?.[0] ||
      'Anonim';

    console.log(
      'Overlay abone adı:',
      name
    );

    broadcast({
      type: 'sub',
      name,
      event: eventType,
    });

    res.status(200).end();
  }
);

// ---------- 5) WebSocket ----------

const server =
  http.createServer(app);

const wss =
  new WebSocketServer({
    server,
    path: '/ws',
  });

function broadcast(payload) {
  const msg =
    JSON.stringify(payload);

  wss.clients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(msg);
    }
  });
}

wss.on('connection', (socket) => {
  console.log(
    'Overlay WebSocket bağlandı.'
  );

  socket.send(
    JSON.stringify({
      type: 'connected',
    })
  );

  socket.on('close', () => {
    console.log(
      'Overlay WebSocket bağlantısı kapandı.'
    );
  });
});

// ---------- 6) Overlay ----------

app.use(express.static(__dirname));
// ---------- 7) Manuel test ----------

app.get(
  '/test/:name',
  (req, res) => {
    broadcast({
      type: 'sub',
      name: req.params.name,
      event: 'test',
    });

    res.send(
      'gönderildi: ' +
      req.params.name
    );
  }
);

// ---------- 8) Client credentials test ----------
// Bu endpoint sadece teşhis için.

app.get(
  '/test-credentials',
  async (req, res) => {
    try {
      const body =
        new URLSearchParams({
          grant_type:
            'client_credentials',

          client_id:
            CLIENT_ID,

          client_secret:
            CLIENT_SECRET,
        });

      const r = await fetch(
        'https://id.kick.com/oauth/token',
        {
          method: 'POST',

          headers: {
            'Content-Type':
              'application/x-www-form-urlencoded',
          },

          body,
        }
      );

      const raw =
        await r.text();

      console.log(
        'CLIENT CREDENTIALS TEST:',
        r.status
      );

      res
        .status(r.status)
        .send(
          `Kick cevap: ${r.status}<br><pre>${raw}</pre>`
        );

    } catch (err) {
      console.error(err);

      res
        .status(500)
        .send(err.message);
    }
  }
);

// ---------- Server ----------

server.listen(
  PORT,
  () => {
    console.log(
      `Kick köprüsü çalışıyor: http://localhost:${PORT}`
    );

    console.log(
      `1) http://localhost:${PORT}/auth -> Kick hesabınla giriş yap`
    );

    console.log(
      `2) http://localhost:${PORT}/subscribe -> event aboneliğini kur`
    );

    console.log(
      `3) OBS Browser Source -> http://localhost:${PORT}/overlay?ws=ws://localhost:${PORT}/ws&demo=0`
    );
  }
);
