const assert = require('assert');
const fs = require('fs');
const path = require('path');
const tls = require('tls');
const { Client: SSHClient, utils } = require('ssh2');
const { sunucuOlustur } = require('../server');
const { loglariOku } = require('../core');

async function guvenlikVeIslevsellikTestleriniCalistir() {
  console.log('\x1b[1;34m=== SHADOWLINE GÜVENLİK VE İŞLEVSELLİK DOĞRULAMA TESTLERİ ===\x1b[0m');

  const testLog = path.join(__dirname, '..', 'logs', 'sec-test.enc.log');
  if (fs.existsSync(testLog)) fs.unlinkSync(testLog);

  const testLogKey = 'guvenlik-test-log-anahtari-32b-secure';
  const kayitliEdKey = utils.generateKeyPairSync('ed25519');
  const yanlisEdKey = utils.generateKeyPairSync('ed25519');

  const sunucu = sunucuOlustur({
    sshKullanicilari: {
      samsepi0l: kayitliEdKey.public
    },
    logDosyasi: testLog,
    anaLogSifresi: testLogKey
  });

  const { sshPort, clientPort } = await sunucu.baslat(0, 0);

  // TLS İstemci Yardımcısı
  function tlsIstemciBagla(kullaniciAdi) {
    return new Promise((resolve, reject) => {
      const mesajlar = [];
      let tampon = '';
      let kapandi = false;

      const certPath = path.join(__dirname, '..', 'keys', 'tls_cert.pem');
      const soket = tls.connect({
        host: '127.0.0.1',
        port: clientPort,
        rejectUnauthorized: false,
        checkServerIdentity: () => undefined
      }, () => {
        soket.write(JSON.stringify({ kullaniciAdi }) + '\n');
      });

      soket.on('data', (d) => {
        tampon += d.toString('utf8');
        const satirlar = tampon.split('\n');
        tampon = satirlar.pop();
        for (const s of satirlar) {
          if (!s.trim()) continue;
          try {
            const p = JSON.parse(s);
            if (p.metin) mesajlar.push(p.metin);
          } catch {}
        }
      });

      soket.on('close', () => { kapandi = true; });
      soket.on('error', () => { kapandi = true; });

      // Bağlantı kurulup ilk logo / mesajlar gelene kadar kısa bekleme
      setTimeout(() => {
        resolve({
          soket,
          mesajlar,
          yaz: (metin) => soket.write(JSON.stringify({ metin }) + '\n'),
          kapat: () => soket.destroy(),
          isClosed: () => kapandi
        });
      }, 250);
    });
  }

  // SSH İstemci Yardımcısı
  function sshBaglan({ username, privateKey, tryPassword }) {
    return new Promise((resolve, reject) => {
      const istemci = new SSHClient();
      let cikti = '';

      istemci.on('ready', () => {
        istemci.shell({ cols: 100, rows: 26 }, (err, stream) => {
          if (err) return reject(err);
          stream.on('data', (d) => { cikti += d.toString('utf8'); });
          resolve({
            istemci,
            stream,
            getCikti: () => cikti,
            yaz: (t) => stream.write(t + '\r'),
            kapat: () => istemci.end()
          });
        });
      });

      istemci.on('error', (err) => reject(err));

      const connectOpts = {
        host: '127.0.0.1',
        port: sshPort,
        username
      };
      if (privateKey) connectOpts.privateKey = privateKey;
      if (tryPassword) connectOpts.password = 'rastgeleSifre';

      istemci.connect(connectOpts);
    });
  }

  // --------------------------------------------------------------------------
  // TEST 1: Kullanıcı Bildirim Metni (Transparency Notice)
  // --------------------------------------------------------------------------
  const istemciA = await tlsIstemciBagla('elliot');
  assert(
    istemciA.mesajlar.some(m => m.includes('şifreli denetim kayıtlarından okunabilir')),
    'TEST 1 BAŞARISIZ: Kullanıcıya şifreli denetim kaydı bildirimi gösterilmedi!'
  );
  console.log('[GEÇTİ] Test 1: Şifreli denetim kaydı şeffaflık bildirimi istemciye gösterildi.');

  // --------------------------------------------------------------------------
  // TEST 2: /reply ve /r - Ad Değişikliği Sonrası Teslimat
  // --------------------------------------------------------------------------
  const istemciB = await tlsIstemciBagla('darlene');
  await new Promise(r => setTimeout(r, 200));

  // A -> B'ye özel mesaj atar
  istemciA.yaz('/msg darlene selam darlene');
  await new Promise(r => setTimeout(r, 200));
  assert(
    istemciB.mesajlar.some(m => m.includes('selam darlene')),
    'TEST 2A BAŞARISIZ: İlk özel mesaj darlene kullanıcısına ulaşmadı!'
  );

  // B adını değiştirir (/nick darlene_hacker)
  istemciB.yaz('/nick darlene_hacker');
  await new Promise(r => setTimeout(r, 200));

  // A şimdi /reply ile cevap verir
  istemciA.yaz('/reply adini degistirsen de buradayim');
  await new Promise(r => setTimeout(r, 200));
  assert(
    istemciB.mesajlar.some(m => m.includes('adini degistirsen de buradayim')),
    'TEST 2B BAŞARISIZ: Karşı taraf adını değiştirdikten sonra /reply mesajı oturuma ulaşmadı!'
  );
  console.log('[GEÇTİ] Test 2: Takma ad değişikliği sonrası /reply değişmeyen oturum ID\'sine başarıyla ulaştı.');

  // --------------------------------------------------------------------------
  // TEST 3: Bağlantı Kesilmesi ve Eski Adın Başkası Tarafından Alınması
  // --------------------------------------------------------------------------
  // B (darlene_hacker) bağlantısını kapatır
  istemciB.kapat();
  await new Promise(r => setTimeout(r, 250));

  // A şimdi /reply dener -> Hata almalı ve mesaj teslim edilmemeli
  istemciA.yaz('/reply orda misin?');
  await new Promise(r => setTimeout(r, 200));
  assert(
    istemciA.mesajlar.some(m => m.includes('otumu kapandı') || m.includes('oturumu kapandı')),
    'TEST 3A BAŞARISIZ: Bağlantı kesilince /reply teslimatı açık hata bildirmedi!'
  );

  // Başka biri (Saldırgan/Yeni kullanıcı) 'darlene' veya 'darlene_hacker' adıyla bağlanır
  const sahteDarlene = await tlsIstemciBagla('darlene');
  await new Promise(r => setTimeout(r, 200));

  // A tekrar /reply dener -> Yeni bağlanan kullanıcıya ASLA gitmemeli
  istemciA.yaz('/reply eski oturuma gitmeli yenisine degil');
  await new Promise(r => setTimeout(r, 200));
  assert(
    !sahteDarlene.mesajlar.some(m => m.includes('eski oturuma gitmeli yenisine degil')),
    'TEST 3B BAŞARISIZ: Eski adla yeniden bağlanan kişi önceki oturumun /reply mesajını çalabildi!'
  );
  console.log('[GEÇTİ] Test 3: Bağlantı kesilince teslimat durdu, aynı isimle bağlanan yeni oturuma sızma engellendi.');
  sahteDarlene.kapat();

  // --------------------------------------------------------------------------
  // TEST 4: SSH Sohbet Portunda Yanlış Anahtar ile Kayıtlı İsim Girişi
  // --------------------------------------------------------------------------
  let yanlisAnahtarReddedildi = false;
  try {
    await sshBaglan({ username: 'samsepi0l', privateKey: yanlisEdKey.private });
  } catch {
    yanlisAnahtarReddedildi = true;
  }
  assert(yanlisAnahtarReddedildi, 'TEST 4 BAŞARISIZ: Kayıtlı isim yanlış SSH anahtarıyla içeri alındı!');
  console.log('[GEÇTİ] Test 4: Kayıtlı takma ada ait yanlış SSH açık anahtarlı giriş anında reddedildi.');

  // --------------------------------------------------------------------------
  // TEST 5: SSH Sohbet Portunda İmzasız / Şifreli Giriş Denemesi
  // --------------------------------------------------------------------------
  let imzasizGirisReddedildi = false;
  try {
    await sshBaglan({ username: 'samsepi0l', tryPassword: true });
  } catch {
    imzasizGirisReddedildi = true;
  }
  assert(imzasizGirisReddedildi, 'TEST 5 BAŞARISIZ: Kayıtlı isim SSH şifre/imzasız metotla içeri alındı!');
  console.log('[GEÇTİ] Test 5: Kayıtlı ada ait imzasız/şifreli giriş denemesi reddedildi.');

  // --------------------------------------------------------------------------
  // TEST 6: Doğru SSH Anahtarı ile Başarılı Giriş
  // --------------------------------------------------------------------------
  const dogruSsh = await sshBaglan({ username: 'samsepi0l', privateKey: kayitliEdKey.private });
  await new Promise(r => setTimeout(r, 300));
  assert(
    dogruSsh.getCikti().includes('ShadowLine') || dogruSsh.getCikti().includes('BitchX'),
    'TEST 6 BAŞARISIZ: Doğru anahtarla SSH girişi yapılamadı!'
  );
  console.log('[GEÇTİ] Test 6: Doğru SSH anahtarıyla kayıtlı kullanıcı (samsepi0l) başarıyla giriş yaptı.');

  // --------------------------------------------------------------------------
  // TEST 7: TLS / TCP İstemcisi Üzerinden Kayıtlı Ad Talebi (Yetkisiz Nick)
  // --------------------------------------------------------------------------
  const yetkisizNickClient = await tlsIstemciBagla('samsepi0l');
  await new Promise(r => setTimeout(r, 200));
  assert(
    yetkisizNickClient.isClosed() || yetkisizNickClient.mesajlar.some(m => m.includes('Bu isim kayıtlıdır')),
    'TEST 7 BAŞARISIZ: TLS/TCP istemcisi kayıtlı SSH adını alabildi!'
  );
  console.log('[GEÇTİ] Test 7: TLS istemcisi üzerinden kayıtlı ad (samsepi0l) talebi engellendi.');

  // Büyük/küçük harf varyasyonu ile kayıtlı ad denemesi
  const yetkisizNickCase = await tlsIstemciBagla('SaMsEpI0L');
  await new Promise(r => setTimeout(r, 200));
  assert(
    yetkisizNickCase.isClosed() || yetkisizNickCase.mesajlar.some(m => m.includes('Bu isim kayıtlıdır')),
    'TEST 7-B BAŞARISIZ: Kayıtlı ad büyük/küçük harf varyasyonuyla TLS üzerinden alınabildi!'
  );
  console.log('[GEÇTİ] Test 7-B: Kayıtlı adın büyük-küçük harf varyasyonu (SaMsEpI0L) engellendi.');

  // --------------------------------------------------------------------------
  // TEST 8: Parolalı Odalarda Üyelik Denetimi ve Varsayılan Oda Parolası
  // --------------------------------------------------------------------------
  // Yetkisiz kullanıcı (/key) dener ve reddedilir (dogruSsh yönetici değil, istemciA yönetici)
  dogruSsh.yaz('/key izinsizSifre');
  await new Promise(r => setTimeout(r, 200));
  assert(
    dogruSsh.getCikti().includes('Sadece oda yöneticisi'),
    'TEST 8-0 BAŞARISIZ: Yetkisiz kullanıcı oda şifresi değiştirebildi!'
  );
  console.log('[GEÇTİ] Test 8-0: Yetkisiz kullanıcının oda şifresi değiştirme denemesi engellendi.');

  // Oda yöneticisi (istemciA) odayı şifreler (/key gizlisifre123)
  istemciA.yaz('/key gizlisifre123');
  await new Promise(r => setTimeout(r, 300));

  // Yeni bir kullanıcı bağlanır. Varsayılan oda (#fsociety) artık şifreli olduğu için giriş başarısız olmalıdır.
  const davetsizMisafir = await tlsIstemciBagla('trenton');
  await new Promise(r => setTimeout(r, 300));

  assert(
    davetsizMisafir.mesajlar.some(m => m.includes('şifreli') && m.includes('Yanlış şifre')),
    'TEST 8A BAŞARISIZ: Parolalı varsayılan odaya izinsiz giriş uyarısı verilmedi!'
  );

  // Davetsiz misafir odaya mesaj yazmayı dener
  davetsizMisafir.yaz('gizli konusmalari goruyor muyum?');
  await new Promise(r => setTimeout(r, 200));

  assert(
    !dogruSsh.getCikti().includes('gizli konusmalari goruyor muyum?'),
    'TEST 8B BAŞARISIZ: Odaya katılamayan kullanıcı odaya mesaj yayınlayabildi!'
  );
  assert(
    davetsizMisafir.mesajlar.some(m => m.includes('üye değilsiniz')),
    'TEST 8C BAŞARISIZ: Üye olmayan kullanıcıya uyarı iletilmedi!'
  );

  // Davetsiz misafir /who ile üye listesini görmeyi dener
  davetsizMisafir.yaz('/who');
  await new Promise(r => setTimeout(r, 200));
  assert(
    !davetsizMisafir.mesajlar.some(m => m.includes('samsepi0l')),
    'TEST 8D BAŞARISIZ: Odaya üye olmayan kullanıcı /who ile üyeleri görebildi!'
  );
  console.log('[GEÇTİ] Test 8: Parolalı varsayılan odaya reddedilen kullanıcı odaya yazamadı ve /who üyelerini göremedi.');

  // --------------------------------------------------------------------------
  // TEST 10: Yeni IRC Özellikleri (/topic, /me, /kick, /away, mention bell)
  // --------------------------------------------------------------------------
  // /me aksiyon mesajı testi
  istemciA.yaz('/me kod yaziyor');
  await new Promise(r => setTimeout(r, 300));
  assert(
    dogruSsh.getCikti().includes('* elliot kod yaziyor'),
    'TEST 10A BAŞARISIZ: /me aksiyon mesajı yayınlanmadı!'
  );
  console.log('[GEÇTİ] Test 10-A: /me aksiyon mesajı başarıyla yayınlandı (* elliot kod yaziyor).');

  // /topic testi: Yönetici (istemciA) başlık değiştirir
  istemciA.yaz('/topic fsociety operasyonu aktif');
  await new Promise(r => setTimeout(r, 300));
  assert(
    dogruSsh.getCikti().includes('oda başlığını değiştirdi') && dogruSsh.getCikti().includes('fsociety operasyonu aktif'),
    'TEST 10B BAŞARISIZ: /topic oda başlığı değiştirilemedi!'
  );
  console.log('[GEÇTİ] Test 10-B: /topic oda başlığı yönetici tarafından başarıyla güncellendi.');

  // /away testi: samsepi0l uzakta moduna geçer, elliot DM atınca bildirim alır
  dogruSsh.yaz('/away kahve molasindayim');
  await new Promise(r => setTimeout(r, 300));
  istemciA.yaz('/msg samsepi0l orada misin');
  await new Promise(r => setTimeout(r, 300));
  assert(
    istemciA.mesajlar.some(m => m.includes('[UZAKTA]') && m.includes('kahve molasindayim')),
    'TEST 10C BAŞARISIZ: /away otomatik yanıtı dönmedi!'
  );
  console.log('[GEÇTİ] Test 10-C: /away uzakta modu özel mesajlarda otomatik yanıt döndü.');

  // /kick testi: Yönetici (istemciA) samsepi0l kullanıcısını atar
  istemciA.yaz('/kick samsepi0l kural ihlali');
  await new Promise(r => setTimeout(r, 400));
  assert(
    dogruSsh.getCikti().includes('odasından atıldınız: kural ihlali'),
    'TEST 10D BAŞARISIZ: /kick ile kullanıcı odadan atılmadı!'
  );
  console.log('[GEÇTİ] Test 10-D: /kick ile kullanıcı odadan çıkarıldı ve lobiye gönderildi.');

  // --------------------------------------------------------------------------
  // TEST 11: Şifreli Denetim Loglarının Bütünlüğü ve Okunabilirliği
  // --------------------------------------------------------------------------
  const loglar = loglariOku(testLog, testLogKey);
  assert(loglar.length > 5, 'TEST 11A BAŞARISIZ: Denetim logları diske yazılmamış!');
  assert(
    loglar.some(l => l.olay === 'OZEL_MESAJ' && l.kullaniciAdi === 'elliot'),
    'TEST 11B BAŞARISIZ: Özel mesaj log kaydında bulunamadı!'
  );
  assert(
    loglar.some(l => l.olay === 'YETKI_HATASI'),
    'TEST 11C BAŞARISIZ: Yetki hatası log kaydında bulunamadı!'
  );
  assert(
    loglar.some(l => l.olay === 'AKSIYON' && l.kullaniciAdi === 'elliot'),
    'TEST 11D BAŞARISIZ: Aksiyon (/me) log kaydında bulunamadı!'
  );
  assert(
    loglar.some(l => l.olay === 'KICK'),
    'TEST 11E BAŞARISIZ: Kick log kaydında bulunamadı!'
  );
  console.log(`[GEÇTİ] Test 11: Şifreli denetim kayıtları (${loglar.length} olay) başarıyla doğrulandı ve okundu.`);

  // Temizlik
  istemciA.kapat();
  dogruSsh.kapat();
  davetsizMisafir.kapat();
  await sunucu.durdur();
  if (fs.existsSync(testLog)) fs.unlinkSync(testLog);

  console.log('\n\x1b[1;32m>>> TÜM GÜVENLİK, OTURUM VE DENETİM TESTLERİ BAŞARIYLA GEÇTİ! <<<\x1b[0m\n');
}

guvenlikVeIslevsellikTestleriniCalistir().catch((err) => {
  console.error('\x1b[1;31mTESTTE HATA:\x1b[0m', err);
  process.exit(1);
});
