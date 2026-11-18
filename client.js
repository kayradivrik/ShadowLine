/**
 * SHADOWLINE TLS İSTEMCİSİ (client.js)
 * -------------------------------------------------------------
 * Sunucuya standart TLS üzerinden güvenli olarak bağlanır.
 * 
 * Kullanım:
 *   npm run client -- [kullaniciAdi] [sunucuIp] [port]
 * Örnek:
 *   npm run client -- d0loresH4ze
 */

const tls = require('tls');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { AYARLAR } = require('./core');

// ============================================================================
// 1. BAĞLANTI AYARLARINI HAZIRLAMA
// ============================================================================
const kullaniciAdi = process.argv[2] || 'd0loresH4ze';
const sunucuIp = process.argv[3] || process.env.HOST || '127.0.0.1';
const sunucuPort = Number(process.argv[4] || AYARLAR.CLIENT_PORT);

const certPath = path.join(__dirname, 'keys', 'tls_cert.pem');
const tlsOptions = {
  host: sunucuIp,
  port: sunucuPort,
  rejectUnauthorized: false,
  checkServerIdentity: () => undefined
};

if (fs.existsSync(certPath)) {
  try {
    tlsOptions.ca = [fs.readFileSync(certPath)];
  } catch {}
}

const baglanti = tls.connect(tlsOptions);

function komutTamamla(satir) {
  const komutlar = [
    '/join', '/msg', '/reply', '/nick', '/me', '/topic', '/kick', '/away',
    '/key', '/secret', '/who', '/list', '/clear', '/help', '/quit'
  ];
  if (satir.startsWith('/') && !satir.includes(' ')) {
    const eslesenler = komutlar.filter((k) => k.startsWith(satir.toLowerCase()));
    return [eslesenler.length ? eslesenler : komutlar, satir];
  }
  return [[], satir];
}

const klavyeOkuyucu = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  completer: komutTamamla
});

function sunucuyaGonder(veriNesnesi) {
  if (baglanti.writable) {
    baglanti.write(JSON.stringify(veriNesnesi) + '\n');
  }
}

// ============================================================================
// 2. BAĞLANTI OLAYLARI VE DİNLEYİCİLER
// ============================================================================
baglanti.on('secureConnect', () => {
  sunucuyaGonder({ kullaniciAdi });
  klavyeOkuyucu.setPrompt('\x1b[1;36m[ShadowLine] > \x1b[0m');
  klavyeOkuyucu.prompt();
});

let gelenVeriTamponu = '';
baglanti.on('data', (parca) => {
  gelenVeriTamponu += parca.toString('utf8');

  const satirlar = gelenVeriTamponu.split('\n');
  gelenVeriTamponu = satirlar.pop();

  for (const satir of satirlar) {
    if (!satir.trim()) continue;

    try {
      const cozulmusPaket = JSON.parse(satir);
      readline.clearLine(process.stdout, 0);
      readline.cursorTo(process.stdout, 0);
      if (cozulmusPaket.metin) {
        console.log(cozulmusPaket.metin);
      }
      if (cozulmusPaket.hata) {
        baglanti.end();
        process.exit(1);
      }
      klavyeOkuyucu.prompt(true);
    } catch {}
  }
});

klavyeOkuyucu.on('line', (yazilanSatir) => {
  const temizMetin = yazilanSatir.trim();

  if (temizMetin) {
    process.stdout.write('\x1b[1A\r\x1b[2K');
    sunucuyaGonder({ metin: temizMetin });
  }

  klavyeOkuyucu.prompt();
});

baglanti.on('close', () => {
  console.log('\x1b[1;31mSunucu bağlantısı kapandı.\x1b[0m');
  process.exit(0);
});

baglanti.on('error', (hata) => {
  console.error('\x1b[1;31mBağlantı hatası:\x1b[0m', hata.message);
});
