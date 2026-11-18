const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================================================
// 1. AYARLARIN (.env) YÖNETİMİ
// ============================================================================
const envDosyaYolu = path.join(__dirname, '.env');

function rastgele32ByteHex() {
  return crypto.randomBytes(32).toString('hex');
}

// .env dosyasını satır satır okuyup bir Javascript objesine dönüştürüyoruz
const okunanEnv = {};
if (fs.existsSync(envDosyaYolu)) {
  const dosyaIcerigi = fs.readFileSync(envDosyaYolu, 'utf8');
  for (const satir of dosyaIcerigi.split(/\r?\n/)) {
    const esittirIndeksi = satir.indexOf('=');
    if (esittirIndeksi > 0 && !satir.trim().startsWith('#')) {
      const anahtar = satir.slice(0, esittirIndeksi).trim();
      const deger = satir.slice(esittirIndeksi + 1).trim();
      okunanEnv[anahtar] = deger;
    }
  }
}

// Eksik sırları kriptografik olarak güvenli 32 rastgele bayttan üretip .env dosyasına yaz
const eklenecekler = [];
if (!okunanEnv.MASTER_LOG_KEY) {
  okunanEnv.MASTER_LOG_KEY = rastgele32ByteHex();
  eklenecekler.push(`MASTER_LOG_KEY=${okunanEnv.MASTER_LOG_KEY}`);
}
if (!okunanEnv.TRANSPORT_SECRET) {
  okunanEnv.TRANSPORT_SECRET = rastgele32ByteHex();
  eklenecekler.push(`TRANSPORT_SECRET=${okunanEnv.TRANSPORT_SECRET}`);
}
if (!okunanEnv.IP_CLOAK_SECRET) {
  okunanEnv.IP_CLOAK_SECRET = rastgele32ByteHex();
  eklenecekler.push(`IP_CLOAK_SECRET=${okunanEnv.IP_CLOAK_SECRET}`);
}

if (!fs.existsSync(envDosyaYolu)) {
  const varsayilanAyarlar = [
    'SSH_PORT=2222',
    'CLIENT_PORT=6697',
    'HOST=0.0.0.0',
    'SERVER_NAME=irc.whononymous.net',
    'DEFAULT_CHANNEL=#fsociety',
    `MASTER_LOG_KEY=${okunanEnv.MASTER_LOG_KEY}`,
    `TRANSPORT_SECRET=${okunanEnv.TRANSPORT_SECRET}`,
    `IP_CLOAK_SECRET=${okunanEnv.IP_CLOAK_SECRET}`
  ].join('\n') + '\n';
  fs.writeFileSync(envDosyaYolu, varsayilanAyarlar, { mode: 0o600 });
} else if (eklenecekler.length > 0) {
  fs.appendFileSync(envDosyaYolu, '\n' + eklenecekler.join('\n') + '\n', { mode: 0o600 });
}

// Projenin genelinde kullanılacak temel ayarlar
const AYARLAR = {
  SSH_PORT: Number(okunanEnv.SSH_PORT || 2222),
  CLIENT_PORT: Number(okunanEnv.CLIENT_PORT || 6697),
  HOST: okunanEnv.HOST || '0.0.0.0',
  SERVER_NAME: okunanEnv.SERVER_NAME || 'irc.whononymous.net',
  DEFAULT_CHANNEL: okunanEnv.DEFAULT_CHANNEL || '#fsociety',
  MASTER_LOG_KEY: okunanEnv.MASTER_LOG_KEY,
  TRANSPORT_SECRET: okunanEnv.TRANSPORT_SECRET,
  IP_CLOAK_SECRET: okunanEnv.IP_CLOAK_SECRET,
  LOG_DOSYASI: path.join(__dirname, 'logs', 'audit.enc.log'),
  SSH_ANAHTAR_DOSYASI: path.join(__dirname, 'keys', 'ssh_host_rsa_key'),
  TLS_CERT_DOSYASI: path.join(__dirname, 'keys', 'tls_cert.pem'),
  TLS_KEY_DOSYASI: path.join(__dirname, 'keys', 'tls_key.pem')
};

// Log ve Anahtar klasörleri yoksa otomatik oluştur
fs.mkdirSync(path.dirname(AYARLAR.LOG_DOSYASI), { recursive: true });
fs.mkdirSync(path.dirname(AYARLAR.SSH_ANAHTAR_DOSYASI), { recursive: true });

// ============================================================================
// 2. KRİPTOGRAFİ (AES-256-GCM ŞİFRELEME)
// ============================================================================
const anahtarBellegi = new Map();

/**
 * Verilen metin parolasından scrypt algoritması ile 256-bit (32 byte)
 * güvenli bir şifreleme anahtarı üretir.
 */
function gizliAnahtarUret(parola) {
  if (!parola) {
    throw new Error('Şifreleme için anahtar belirtilmedi!');
  }
  if (!anahtarBellegi.has(parola)) {
    const uretilenAnahtar = crypto.scryptSync(String(parola), 'whononymous_tuz', 32);
    anahtarBellegi.set(parola, uretilenAnahtar);
  }
  return anahtarBellegi.get(parola);
}

/**
 * Herhangi bir JSON objesini veya metni AES-256-GCM ile şifreler.
 * Çıktı formatı: v1:IV:AUTH_TAG:ENCRYPTED_DATA
 */
function veriyiSifrele(veri, parola = AYARLAR.TRANSPORT_SECRET) {
  const rastgeleIv = crypto.randomBytes(12);
  const anahtar = gizliAnahtarUret(parola);

  const sifreleyici = crypto.createCipheriv('aes-256-gcm', anahtar, rastgeleIv);
  const jsonMetni = JSON.stringify(veri);

  const sifreliVeri = Buffer.concat([
    sifreleyici.update(jsonMetni, 'utf8'),
    sifreleyici.final()
  ]);

  const dogrulamaEtiketi = sifreleyici.getAuthTag();

  return [
    'v1',
    rastgeleIv.toString('base64'),
    dogrulamaEtiketi.toString('base64'),
    sifreliVeri.toString('base64')
  ].join(':');
}

/**
 * Şifreli metni çözer ve orijinal JSON objesi olarak geri verir.
 * Eğer şifre yanlışsa veya veriyle oynanmışsa hata fırlatır.
 */
function sifreyiCoz(sifreliMetin, parola = AYARLAR.TRANSPORT_SECRET) {
  const parcalar = String(sifreliMetin).trim().split(':');
  const [versiyon, ivBase64, etiketBase64, veriBase64] = parcalar;

  if (versiyon !== 'v1' || !veriBase64) {
    throw new Error('Geçersiz veya bozuk şifreli veri!');
  }

  const anahtar = gizliAnahtarUret(parola);
  const iv = Buffer.from(ivBase64, 'base64');
  const dogrulamaEtiketi = Buffer.from(etiketBase64, 'base64');
  const sifreliVeri = Buffer.from(veriBase64, 'base64');

  const cozucu = crypto.createDecipheriv('aes-256-gcm', anahtar, iv);
  cozucu.setAuthTag(dogrulamaEtiketi);

  const cozulmusTampon = Buffer.concat([
    cozucu.update(sifreliVeri),
    cozucu.final()
  ]);

  return JSON.parse(cozulmusTampon.toString('utf8'));
}

// ============================================================================
// 3. AĞ VE KİMLİK YARDIMCILARI
// ============================================================================
/**
 * IPv6 içinde gizlenen IPv4 adreslerini temizler. (Örn: ::ffff:192.168.1.1 -> 192.168.1.1)
 */
function ipTemizle(hamIp = '') {
  return String(hamIp || '').replace(/^::ffff:/, '') || 'bilinmiyor';
}

/**
 * Kullanıcıların birbirlerinin gerçek IP adresini görmesini engeller.
 * IP adresini güvenli tuz (IP_CLOAK_SECRET) ile hashleyerek sahte bir .onion adresi üretir.
 */
function ipGizle(gercekIp) {
  const temizIp = ipTemizle(gercekIp);
  const tuz = AYARLAR.IP_CLOAK_SECRET || 'varsayilan_gecici_tuz';
  const karmaKod = crypto
    .createHmac('sha256', tuz)
    .update(temizIp)
    .digest('hex')
    .slice(0, 8);

  return `${karmaKod}.whononymous.onion`;
}

/**
 * SSH Sunucusu için RSA anahtarı döndürür, yoksa üretir.
 */
function sshSunucuAnahtariAl() {
  if (!fs.existsSync(AYARLAR.SSH_ANAHTAR_DOSYASI)) {
    const { privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' }
    });
    fs.writeFileSync(AYARLAR.SSH_ANAHTAR_DOSYASI, privateKey, { mode: 0o600 });
  }
  return fs.readFileSync(AYARLAR.SSH_ANAHTAR_DOSYASI);
}

/**
 * TLS Sunucusu için sertifika ve anahtar döndürür.
 */
function tlsSertifikasiAl() {
  if (!fs.existsSync(AYARLAR.TLS_CERT_DOSYASI) || !fs.existsSync(AYARLAR.TLS_KEY_DOSYASI)) {
    throw new Error('TLS sertifika dosyaları bulunamadı: ' + AYARLAR.TLS_CERT_DOSYASI);
  }
  return {
    cert: fs.readFileSync(AYARLAR.TLS_CERT_DOSYASI),
    key: fs.readFileSync(AYARLAR.TLS_KEY_DOSYASI)
  };
}

// ============================================================================
// 4. ŞİFRELİ DENETİM LOGLARI (AUDIT LOGS)
// ============================================================================
/**
 * Sunucudaki olayları (kim, hangi IP'den, ne mesaj attı)
 * diske tamamen AES-256-GCM ile şifreli olarak kaydeder.
 */
function logKaydet(olayBilgisi, logDosyasi = AYARLAR.LOG_DOSYASI, anaSifre = AYARLAR.MASTER_LOG_KEY) {
  const kaydedilecekVeri = {
    zaman: new Date().toISOString(),
    olay: olayBilgisi.olay,
    ip: ipTemizle(olayBilgisi.ip),
    port: olayBilgisi.port,
    baglantiTuru: olayBilgisi.baglantiTuru,
    kullaniciAdi: olayBilgisi.kullaniciAdi,
    hedef: olayBilgisi.hedef,
    mesaj: olayBilgisi.mesaj
  };

  const sifreliSatir = veriyiSifrele(kaydedilecekVeri, anaSifre);
  fs.appendFileSync(logDosyasi, sifreliSatir + '\n', { mode: 0o600 });
}

/**
 * Şifreli log dosyasını okur ve çözüp bir liste halinde döndürür.
 */
function loglariOku(logDosyasi = AYARLAR.LOG_DOSYASI, anaSifre = AYARLAR.MASTER_LOG_KEY) {
  if (!fs.existsSync(logDosyasi)) return [];

  const satirlar = fs.readFileSync(logDosyasi, 'utf8').split(/\r?\n/).filter(Boolean);
  return satirlar.map((satir, siraNo) => {
    try {
      return sifreyiCoz(satir, anaSifre);
    } catch {
      return { hata: true, satirNo: siraNo + 1 };
    }
  });
}

module.exports = {
  AYARLAR,
  veriyiSifrele,
  sifreyiCoz,
  ipTemizle,
  ipGizle,
  sshSunucuAnahtariAl,
  tlsSertifikasiAl,
  logKaydet,
  loglariOku
};
