const assert = require('assert');
const fs = require('fs');
const path = require('path');
const tls = require('tls');
const { Client: SSHClient, utils } = require('ssh2');
const { sunucuOlustur } = require('../server');
const { loglariOku } = require('../core');

async function sistemiTestEt() {
  const testLogDosyasi = path.join(__dirname, '..', 'logs', 'test.enc.log');
  if (fs.existsSync(testLogDosyasi)) {
    fs.unlinkSync(testLogDosyasi);
  }

  const testLogSifresi = 'test-log-anahtari-32byte-guvenli-anahtar';
  const anahtar = utils.generateKeyPairSync('ed25519');

  const sunucu = sunucuOlustur({
    sshKullanicilari: { samsepi0l: anahtar.public },
    logDosyasi: testLogDosyasi,
    anaLogSifresi: testLogSifresi
  });

  const { sshPort, clientPort } = await sunucu.baslat(0, 0);

  // 1. samsepi0l SSH ile bağlanır
  let sshEkraniCiktisi = '';
  const sshBaglantisi = await new Promise((tamam, hata) => {
    const istemci = new SSHClient();
    istemci.on('ready', () => {
      istemci.shell({ cols: 100, rows: 26 }, (err, akis) => {
        if (err) return hata(err);
        akis.on('data', (veri) => {
          sshEkraniCiktisi += veri.toString('utf8');
        });
        tamam({ istemci, akis });
      });
    });
    istemci.on('error', hata);
    istemci.connect({
      privateKey: anahtar.private,
      host: '127.0.0.1',
      port: sshPort,
      username: 'samsepi0l'
    });
  });

  // 2. d0loresH4ze TLS istemcisi ile bağlanır
  const gelenMesajlar = [];
  const certPath = path.join(__dirname, '..', 'keys', 'tls_cert.pem');
  const istemciSoketi = await new Promise((tamam) => {
    const soket = tls.connect({
      host: '127.0.0.1',
      port: clientPort,
      rejectUnauthorized: false,
      checkServerIdentity: () => undefined
    }, () => {
      soket.write(JSON.stringify({ kullaniciAdi: 'd0loresH4ze' }) + '\n');
      tamam(soket);
    });

    let tampon = '';
    soket.on('data', (parca) => {
      tampon += parca.toString('utf8');
      const satirlar = tampon.split('\n');
      tampon = satirlar.pop();
      for (const satir of satirlar) {
        if (!satir.trim()) continue;
        try {
          const veri = JSON.parse(satir);
          if (veri.metin) gelenMesajlar.push(veri.metin);
        } catch {}
      }
    });
  });

  await new Promise((bekle) => setTimeout(bekle, 300));

  // 3. Mesajlaşma testleri
  sshBaglantisi.akis.write('hello friend\r');
  await new Promise((bekle) => setTimeout(bekle, 200));

  istemciSoketi.write(JSON.stringify({ metin: '/msg samsepi0l init_1 hazir' }) + '\n');
  await new Promise((bekle) => setTimeout(bekle, 200));

  // 4. Doğrulamalar
  assert(sshEkraniCiktisi.includes('ShadowLine') || sshEkraniCiktisi.includes('BitchX'), 'SSH ekranında logo görünmeli');
  assert(sshEkraniCiktisi.includes('init_1 hazir'), 'Özel mesaj SSH ekranına düşmeli');
  assert(gelenMesajlar.some((m) => m.includes('hello friend')), 'İstemci oda mesajını almalı');

  // 5. Şifreli log doğrulaması
  const loglar = loglariOku(testLogDosyasi, testLogSifresi);
  assert(loglar.length > 0, 'Log dosyasına yazılmış olmalı');
  assert(loglar.some((k) => k.mesaj && k.mesaj.includes('init_1 hazir')), 'Log çözülebilmeli');

  // Temizlik
  sshBaglantisi.istemci.end();
  istemciSoketi.destroy();
  await sunucu.durdur();
  if (fs.existsSync(testLogDosyasi)) {
    fs.unlinkSync(testLogDosyasi);
  }

  console.log('\x1b[1;32m[TESTLER BAŞARIYLA TAMAMLANDI]\x1b[0m');
}

sistemiTestEt().catch((hata) => {
  console.error('\x1b[1;31m[TEST HATASI]:\x1b[0m', hata);
  process.exit(1);
});
