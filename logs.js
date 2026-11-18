/**
 * WHONONYMOUS LOG OKUYUCU (logs.js)
 * -------------------------------------------------------------
 * Bu script sadece sunucu sahibi içindir.
 * Arka planda tutulan AES-256-GCM ile şifrelenmiş log dosyasını
 * MASTER_LOG_KEY kullanarak çözer ve okunaklı bir tablo olarak basar.
 * 
 * Kullanım:
 *   npm run logs                  -> Tüm logları listeler
 *   npm run logs -- --live        -> Canlı olarak yeni logları anlık gösterir
 *   npm run logs -- aranacak_kisi -> Belirli bir kullanıcı veya IP filtreler
 */

const fs = require('fs');
const { AYARLAR, sifreyiCoz, loglariOku } = require('./core');

// ============================================================================
// 1. KOMUT SATIRI PARAMETRELERİNİN AYIKLANMASI
// ============================================================================
const parametreler = process.argv.slice(2);
const canliIzlemeMi = parametreler.includes('--live') || parametreler.includes('-l');
const arananKelime = parametreler.find((p) => !p.startsWith('-'))?.toLowerCase() || '';

// ============================================================================
// 2. LOG SATIRINI FORMATLAYIP EKRANA YAZDIRMA
// ============================================================================
function logSatiriniYazdir(kayit) {
  // Eğer şifre yanlışsa veya dosya bozulmuşsa
  if (kayit.hata) {
    console.log(`\x1b[31m[Satır #${kayit.satirNo}] Şifre çözülemedi! (Yanlış MASTER_LOG_KEY)\x1b[0m`);
    return;
  }

  // Filtreleme yapıldıysa ve satırda o kelime geçmiyorsa ekrana basma
  const birlesikMetin = `${kayit.zaman} ${kayit.ip} ${kayit.kullaniciAdi} ${kayit.hedef} ${kayit.olay} ${kayit.mesaj}`.toLowerCase();
  if (arananKelime && !birlesikMetin.includes(arananKelime)) {
    return;
  }

  // Tablo sütunları için boşluk tamamlama
  const tarihSaat = kayit.zaman.replace('T', ' ').slice(0, 19);
  const ipVePort = `${kayit.ip}:${kayit.port}`.padEnd(20);
  const protokol = String(kayit.baglantiTuru).padEnd(10);
  const olayTuru = String(kayit.olay).padEnd(12);
  const kullanici = String(kayit.kullaniciAdi).padEnd(12);
  const hedef = String(kayit.hedef).padEnd(12);

  console.log(`${tarihSaat} | ${ipVePort} | ${protokol} | ${olayTuru} | ${kullanici} -> ${hedef} | ${kayit.mesaj}`);
}


// ============================================================================
// 3. MEVCUT LOGLARI YAZDIRMA
// ============================================================================
console.log('TARİH & SAAT        | GERÇEK IP:PORT       | PROTOKOL   | OLAY         | KULLANICI    -> HEDEF        | MESAJ');
console.log('-'.repeat(118));

// Dosyadaki geçmiş kayıtları çöz ve bas
const mevcutLoglar = loglariOku();
for (const kayit of mevcutLoglar) {
  logSatiriniYazdir(kayit);
}


// ============================================================================
// 4. CANLI İZLEME (Eğer --live parametresi verildiyse)
// ============================================================================
if (canliIzlemeMi) {
  console.log('--- Canlı İzleme Modu Aktif (Çıkmak için Ctrl+C) ---');

  let sonOkunanBoyut = fs.existsSync(AYARLAR.LOG_DOSYASI)
    ? fs.statSync(AYARLAR.LOG_DOSYASI).size
    : 0;

  // Dosya değiştikçe sadece yeni eklenen byte'ları oku
  fs.watchFile(AYARLAR.LOG_DOSYASI, { interval: 400 }, (guncelDurum) => {
    if (guncelDurum.size <= sonOkunanBoyut) {
      sonOkunanBoyut = guncelDurum.size;
      return;
    }

    const okumaAkisi = fs.createReadStream(AYARLAR.LOG_DOSYASI, {
      start: sonOkunanBoyut,
      end: guncelDurum.size,
      encoding: 'utf8'
    });

    let yeniVeriTamponu = '';
    okumaAkisi.on('data', (parca) => {
      yeniVeriTamponu += parca;
    });

    okumaAkisi.on('end', () => {
      sonOkunanBoyut = guncelDurum.size;
      const yeniSatirlar = yeniVeriTamponu.split(/\r?\n/).filter(Boolean);

      for (const sifreliSatir of yeniSatirlar) {
        try {
          const cozulmusKayit = sifreyiCoz(sifreliSatir, AYARLAR.MASTER_LOG_KEY);
          logSatiriniYazdir(cozulmusKayit);
        } catch {
          logSatiriniYazdir({ hata: true, satirNo: 'CANLI' });
        }
      }
    });
  });
}
