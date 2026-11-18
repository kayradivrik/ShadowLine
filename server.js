/**
 * SHADOWLINE SOHBET SUNUCUSU (server.js)
 * -------------------------------------------------------------
 * 1) Kullanıcı ve Oda yönetimini yapar.
 * 2) Değiştirilemez oturum ID'si (UUID) ile /reply ve /r bağlamı.
 * 3) SSH (2222) portunda açık anahtar doğrulama (chat-users.json).
 * 4) Parolalı oda üyelik kontrolleri ve sunucu tarafı yetki denetimi.
 * 5) TLS İstemci (6697) portunda güvenli taşıma ve kullanıcı doğrulama.
 * 6) Soket kabulünde anlık IP bağlantı limitleri, auth zaman aşımı, girdi boyutu sınırı.
 * 7) /me, /topic, /kick, /away, Tab tamamlama ve mention zil (\x07) bildirimleri.
 */

const tls = require('tls');
const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { Server: SSHServer, utils } = require('ssh2');

const {
  AYARLAR,
  ipTemizle,
  ipGizle,
  sshSunucuAnahtariAl,
  tlsSertifikasiAl,
  logKaydet
} = require('./core');

// Terminal açılış logosu
const ACILIS_LOGOSU = [
  '\x1b[1;36m  ____  _ _       _     \x1b[1;37m__  __\x1b[0m   \x1b[1;32mShadowLine // eps2.2_init_1.asec\x1b[0m',
  '\x1b[1;36m | __ )(_) |_ ___| |__  \x1b[1;37m\\ \\/ /\x1b[0m   \x1b[36mBitchX-1.2.1-final (TLS/SSH-Secured)\x1b[0m',
  '\x1b[1;36m |____/|_|\\__\\___|_| |_|/\x1b[1;37m_/\\_\\\x1b[0m   \x1b[90m"control can sometimes be an illusion"\x1b[0m',
  '\x1b[1;33m[!] BİLDİRİM: Bu sunucudaki oda ve özel mesajlar sunucu sahibi tarafından şifreli denetim kayıtlarından okunabilir.\x1b[0m'
].join('\r\n');

// GÜVENLİK VE LİMİT SABİTLERİ
const MAKSIMUM_MESAJ_UZUNLUGU = 500;
const MESAJ_BEKLEME_SURESI_MS = 250;
const IP_BASINA_MAKS_BAGLANTI = 10;
const KIMLIK_DOGRULAMA_ZAMAN_ASIMI_MS = 15000;
const MAKS_GELEN_VERI_BOYUTU = 8192;

// Sistemde ayrılmış / yasak isimler
const AYRILMIS_ISIMLER = new Set(['kayra', 'root', 'admin', 'system', 'shadowline', 'whononymous']);

function sunucuOlustur(ozelAyarlar = {}) {
  const logDosyasi = ozelAyarlar.logDosyasi || AYARLAR.LOG_DOSYASI;
  const anaLogSifresi = ozelAyarlar.anaLogSifresi || AYARLAR.MASTER_LOG_KEY;
  const kayitDosyasi = path.join(__dirname, 'keys', 'chat-users.json');

  // Kayıtlı SSH kullanıcı açık anahtarlarını yükle
  const kayitlar = ozelAyarlar.sshKullanicilari ?? (fs.existsSync(kayitDosyasi)
    ? JSON.parse(fs.readFileSync(kayitDosyasi, 'utf8')) : {});

  const sshAnahtarlari = new Map(); // kucukHarf -> { originalName, key }
  for (const [ad, deger] of Object.entries(kayitlar)) {
    const kucukAd = ad.toLowerCase().trim();
    const anahtar = utils.parseKey(deger);
    if (!/^[a-z0-9_-]{1,18}$/.test(kucukAd) || anahtar instanceof Error ||
        Array.isArray(anahtar) || (typeof anahtar.getPrivatePEM === 'function' && anahtar.getPrivatePEM())) {
      throw new Error('Geçersiz SSH kullanıcı kaydı: ' + ad);
    }
    sshAnahtarlari.set(kucukAd, { originalName: ad, key: anahtar });
  }

  // RAM'de saklanan aktif durumlar
  const kullanicilar = new Map(); // id (UUID) -> Kullanıcı nesnesi
  const odalar = new Map();       // odaAdi (küçük harf) -> Oda nesnesi

  // Soket seviyesinde bağlantı sayaçları
  const aktifSshSoketleri = new Map(); // ip -> sayi
  const aktifTlsSoketleri = new Map(); // ip -> sayi

  function sayacArtir(map, ip) {
    const temiz = ipTemizle(ip);
    const mevcut = map.get(temiz) || 0;
    map.set(temiz, mevcut + 1);
    return mevcut + 1;
  }

  function sayacAzalt(map, ip) {
    const temiz = ipTemizle(ip);
    const mevcut = map.get(temiz) || 0;
    if (mevcut <= 1) {
      map.delete(temiz);
    } else {
      map.set(temiz, mevcut - 1);
    }
  }

  // ==========================================================================
  // YARDIMCI FONKSİYONLAR
  // ==========================================================================
  function guvenliMetinYap(hamMetin) {
    return String(hamMetin || '')
      .replace(/[\x00-\x1f\x7f]/g, '')
      .trim()
      .slice(0, MAKSIMUM_MESAJ_UZUNLUGU);
  }

  function suAnkiSaat() {
    return new Date().toTimeString().slice(0, 5);
  }

  function sistemMesajiFormatla(metin) {
    return `\x1b[90m[${suAnkiSaat()}]\x1b[0m \x1b[1;36m-!-\x1b[0m ${metin}`;
  }

  function olayiLogla(olayTuru, kullanici, hedef, mesajIcerigi) {
    logKaydet({
      olay: olayTuru,
      ip: kullanici ? kullanici.ip : '0.0.0.0',
      port: kullanici ? kullanici.port : 0,
      baglantiTuru: kullanici ? kullanici.baglantiTuru : 'SISTEM',
      kullaniciAdi: kullanici ? kullanici.kullaniciAdi : 'sistem',
      hedef: hedef,
      mesaj: mesajIcerigi
    }, logDosyasi, anaLogSifresi);
  }

  // ==========================================================================
  // ODA VE KULLANICI YÖNETİMİ
  // ==========================================================================
  function odaGetir(hamOdaAdi, odaSifresi = '') {
    const temizOdaAdi = String(hamOdaAdi || '').replace(/[^a-zA-Z0-9_#-]/g, '').slice(0, 25) || '#fsociety';
    const odaAdi = temizOdaAdi.startsWith('#') ? temizOdaAdi : `#${temizOdaAdi}`;
    const kucukHarfAd = odaAdi.toLowerCase();

    if (!odalar.has(kucukHarfAd)) {
      odalar.set(kucukHarfAd, {
        ad: odaAdi,
        sifre: odaSifresi,
        baslik: '',
        gizliMi: false,
        yoneticiId: null,
        uyeler: new Set()
      });
    }
    return odalar.get(kucukHarfAd);
  }

  function kullaniciBul(arananAd) {
    const kucuk = String(arananAd || '').toLowerCase();
    for (const k of kullanicilar.values()) {
      if (k.kullaniciAdi.toLowerCase() === kucuk) {
        return k;
      }
    }
    return null;
  }

  function odayaDuyur(oda, gonderilecekMetin, gonderenKullanici = null) {
    if (!oda || !oda.uyeler) return;
    for (const uyeId of oda.uyeler) {
      const uye = kullanicilar.get(uyeId);
      if (uye) {
        try {
          let metin = gonderilecekMetin;
          // Eğer üye mention edildiyse bildirim zili ekle (\x07)
          if (gonderenKullanici && uye.id !== gonderenKullanici.id) {
            const regex = new RegExp(`(^|\\s|@)${uye.kullaniciAdi}(\\s|$|:|,)`, 'i');
            if (regex.test(gonderilecekMetin)) {
              metin = `\x07${metin}`;
            }
          }
          uye.mesajGonder(metin);
        } catch {
          kullaniciCikar(uye);
        }
      }
    }
  }

  function odayaKatil(kullanici, istenenOdaAdi, girilenSifre = '') {
    const hedefOda = odaGetir(istenenOdaAdi, girilenSifre);

    if (hedefOda.sifre && hedefOda.sifre !== girilenSifre) {
      olayiLogla('YETKI_HATASI', kullanici, hedefOda.ad, 'Yanlış oda şifresi');
      kullanici.mesajGonder(sistemMesajiFormatla(`\x1b[1;31m${hedefOda.ad} odası şifreli! Yanlış şifre. Kullanım: /join ${hedefOda.ad} <şifre>\x1b[0m`));
      return false;
    }

    if (kullanici.aktifOda) {
      const eskiOda = odalar.get(kullanici.aktifOda.toLowerCase());
      if (eskiOda && eskiOda !== hedefOda) {
        eskiOda.uyeler.delete(kullanici.id);
        if (eskiOda.yoneticiId === kullanici.id) {
          eskiOda.yoneticiId = eskiOda.uyeler.values().next().value || null;
        }
        odayaDuyur(eskiOda, sistemMesajiFormatla(`${kullanici.kullaniciAdi} odadan ayrıldı.`));
      }
    }

    if (hedefOda.uyeler.size === 0) {
      hedefOda.yoneticiId = kullanici.id;
    }

    hedefOda.uyeler.add(kullanici.id);
    kullanici.aktifOda = hedefOda.ad;

    olayiLogla('ODAYA_GIRIS', kullanici, hedefOda.ad, 'Odaya katıldı');
    odayaDuyur(hedefOda, sistemMesajiFormatla(`\x1b[1;37m${kullanici.kullaniciAdi}\x1b[0m [\x1b[36m${kullanici.maskeliAdres}\x1b[0m] \x1b[1;36m${hedefOda.ad}\x1b[0m odasına katıldı.`));

    if (hedefOda.baslik) {
      kullanici.mesajGonder(sistemMesajiFormatla(`Oda Başlığı (${hedefOda.ad}): \x1b[1;36m${hedefOda.baslik}\x1b[0m`));
    }

    const odadakiIsimler = [...hedefOda.uyeler]
      .map((id) => {
        const uye = kullanicilar.get(id);
        return uye ? (hedefOda.yoneticiId === id ? `@${uye.kullaniciAdi}` : uye.kullaniciAdi) : '';
      })
      .filter(Boolean)
      .join(', ');

    kullanici.mesajGonder(sistemMesajiFormatla(`Odadaki kişiler (${hedefOda.ad}): ${odadakiIsimler}`));
    return true;
  }

  function kullaniciKaydet({ kullaniciAdi, ip, port, baglantiTuru, mesajGonder, baglantiyiKapat }) {
    let temizAd = String(kullaniciAdi || 'anonim').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 18) || 'anonim';

    const temelAd = temizAd;
    let ek = 0;
    while (
      kullaniciBul(temizAd) ||
      AYRILMIS_ISIMLER.has(temizAd.toLowerCase()) ||
      (sshAnahtarlari.has(temizAd.toLowerCase()) && !(baglantiTuru === 'SSH' && temizAd.toLowerCase() === kullaniciAdi.toLowerCase()))
    ) {
      ek++;
      temizAd = temelAd.slice(0, 17 - String(ek).length) + '_' + ek;
    }

    const yeniKullanici = {
      id: crypto.randomUUID(),
      kullaniciAdi: temizAd,
      ip: ipTemizle(ip),
      port: port,
      baglantiTuru: baglantiTuru,
      maskeliAdres: `~${temizAd}@${ipGizle(ip)}`,
      aktifOda: null,
      sonMesajlasilanId: null,
      sonMesajZamani: 0,
      uzaktaMesaji: null,
      mesajGonder: mesajGonder,
      baglantiyiKapat: baglantiyiKapat
    };

    kullanicilar.set(yeniKullanici.id, yeniKullanici);
    olayiLogla('BAGLANDI', yeniKullanici, 'lobi', `Sunucuya bağlandı (${baglantiTuru})`);

    yeniKullanici.mesajGonder(ACILIS_LOGOSU);
    yeniKullanici.mesajGonder(sistemMesajiFormatla(`Hoş geldin \x1b[1;37m${yeniKullanici.kullaniciAdi}\x1b[0m [\x1b[36m${yeniKullanici.maskeliAdres}\x1b[0m] | Komutlar: \x1b[1;33m/help\x1b[0m`));

    odayaKatil(yeniKullanici, '#fsociety');
    return yeniKullanici;
  }

  function kullaniciCikar(kullanici) {
    if (!kullanici || !kullanicilar.delete(kullanici.id)) return;

    if (kullanici.aktifOda) {
      const oda = odalar.get(kullanici.aktifOda.toLowerCase());
      if (oda) {
        oda.uyeler.delete(kullanici.id);
        if (oda.yoneticiId === kullanici.id) {
          oda.yoneticiId = oda.uyeler.values().next().value || null;
        }
        odayaDuyur(oda, sistemMesajiFormatla(`\x1b[1;37m${kullanici.kullaniciAdi}\x1b[0m bağlantıyı kapattı.`));
      }
    }
    olayiLogla('AYRILDI', kullanici, kullanici.aktifOda || 'lobi', 'Bağlantı kesildi');
  }

  // ==========================================================================
  // KOMUT VE MESAJ İŞLEYİCİ
  // ==========================================================================
  function mesajVeyaKomutIsle(kullanici, hamSatir) {
    const satir = guvenliMetinYap(hamSatir);
    if (!satir) return;

    const simdi = Date.now();
    if (simdi - kullanici.sonMesajZamani < MESAJ_BEKLEME_SURESI_MS) {
      return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mÇok hızlı mesaj gönderiyorsunuz, lütfen yavaşlayın.\x1b[0m'));
    }
    kullanici.sonMesajZamani = simdi;

    // 1) NORMAL ODA MESAJI
    if (!satir.startsWith('/')) {
      if (!kullanici.aktifOda) {
        return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mHerhangi bir odaya üye değilsiniz. /join <#oda> ile bir odaya katılın.\x1b[0m'));
      }
      const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
      if (!aktifOda || !aktifOda.uyeler.has(kullanici.id)) {
        return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu odaya üye değilsiniz. Mesaj gönderemezsiniz.\x1b[0m'));
      }

      olayiLogla('ODA_MESAJI', kullanici, aktifOda.ad, satir);
      const sifreliEtiketi = aktifOda.sifre ? '\x1b[32m[ŞİFRELİ]\x1b[0m ' : '';
      const yoneticiIsareti = aktifOda.yoneticiId === kullanici.id ? '\x1b[1;32m@\x1b[0m' : '';
      const formatliMesaj = `\x1b[90m[${suAnkiSaat()}]\x1b[0m ${sifreliEtiketi}\x1b[36m<\x1b[0m${yoneticiIsareti}\x1b[1;37m${kullanici.kullaniciAdi}\x1b[0;36m>\x1b[0m ${satir}`;
      odayaDuyur(aktifOda, formatliMesaj, kullanici);
      return;
    }

    // 2) KOMUTLAR
    const kelimeler = satir.slice(1).split(/\s+/);
    const komut = kelimeler[0].toLowerCase();
    const parametreler = kelimeler.slice(1);

    switch (komut) {
      case 'join':
      case 'j':
        if (!parametreler[0]) return kullanici.mesajGonder(sistemMesajiFormatla('Kullanım: /join <#odaAdi> [şifre]'));
        odayaKatil(kullanici, parametreler[0], parametreler[1] || '');
        break;

      case 'nick': {
        const yeniAd = (parametreler[0] || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 18);
        const kucukYeniAd = yeniAd.toLowerCase();
        if (!yeniAd || AYRILMIS_ISIMLER.has(kucukYeniAd) || kullaniciBul(yeniAd) || sshAnahtarlari.has(kucukYeniAd)) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu isim zaten kullanımda, kayıtlı veya geçersiz.\x1b[0m'));
        }
        const eskiAd = kullanici.kullaniciAdi;
        kullanici.kullaniciAdi = yeniAd;
        kullanici.maskeliAdres = `~${yeniAd}@${ipGizle(kullanici.ip)}`;

        if (kullanici.aktifOda) {
          const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
          if (aktifOda) {
            olayiLogla('ISIM_DEGISTI', kullanici, aktifOda.ad, `${eskiAd} -> ${yeniAd}`);
            odayaDuyur(aktifOda, sistemMesajiFormatla(`\x1b[1;37m${eskiAd}\x1b[0m adını \x1b[1;36m${yeniAd}\x1b[0m yaptı.`));
          }
        } else {
          kullanici.mesajGonder(sistemMesajiFormatla(`Yeni adınız: \x1b[1;36m${yeniAd}\x1b[0m`));
        }
        break;
      }

      case 'me': {
        if (!kullanici.aktifOda) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mHerhangi bir odaya üye değilsiniz.\x1b[0m'));
        }
        const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
        if (!aktifOda || !aktifOda.uyeler.has(kullanici.id)) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu odaya üye değilsiniz.\x1b[0m'));
        }
        const aksiyon = parametreler.join(' ');
        if (!aksiyon) return kullanici.mesajGonder(sistemMesajiFormatla('Kullanım: /me <eylem>'));
        olayiLogla('AKSIYON', kullanici, aktifOda.ad, aksiyon);
        const formatli = `\x1b[90m[${suAnkiSaat()}]\x1b[0m \x1b[1;35m* ${kullanici.kullaniciAdi} ${aksiyon}\x1b[0m`;
        odayaDuyur(aktifOda, formatli, kullanici);
        break;
      }

      case 'topic': {
        if (!kullanici.aktifOda) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mHerhangi bir odada değilsiniz.\x1b[0m'));
        }
        const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
        if (!aktifOda || !aktifOda.uyeler.has(kullanici.id)) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu odanın üyesi değilsiniz.\x1b[0m'));
        }
        if (parametreler.length === 0) {
          return kullanici.mesajGonder(sistemMesajiFormatla(`Oda Başlığı (${aktifOda.ad}): ${aktifOda.baslik || '(belirtilmemiş)'}`));
        }
        if (aktifOda.yoneticiId !== kullanici.id) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mSadece oda yöneticisi (@) başlık değiştirebilir.\x1b[0m'));
        }
        aktifOda.baslik = parametreler.join(' ');
        olayiLogla('ODA_BASLIGI', kullanici, aktifOda.ad, aktifOda.baslik);
        odayaDuyur(aktifOda, sistemMesajiFormatla(`\x1b[1;37m${kullanici.kullaniciAdi}\x1b[0m oda başlığını değiştirdi: \x1b[1;36m${aktifOda.baslik}\x1b[0m`));
        break;
      }

      case 'kick': {
        if (!kullanici.aktifOda) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mHerhangi bir odada değilsiniz.\x1b[0m'));
        }
        const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
        if (!aktifOda || !aktifOda.uyeler.has(kullanici.id)) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu odanın üyesi değilsiniz.\x1b[0m'));
        }
        if (aktifOda.yoneticiId !== kullanici.id) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mSadece oda yöneticisi (@) kullanıcı atabilir.\x1b[0m'));
        }
        const hedefAd = parametreler[0];
        if (!hedefAd) return kullanici.mesajGonder(sistemMesajiFormatla('Kullanım: /kick <kullaniciAdi> [sebep]'));
        const hedef = kullaniciBul(hedefAd);
        if (!hedef || !aktifOda.uyeler.has(hedef.id)) {
          return kullanici.mesajGonder(sistemMesajiFormatla(`\x1b[1;31m${hedefAd} kullanıcısı bu odada bulunamadı.\x1b[0m`));
        }
        if (hedef.id === kullanici.id) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mKendinizi odadan atamazsınız.\x1b[0m'));
        }
        const sebep = parametreler.slice(1).join(' ') || 'Oda yöneticisi tarafından çıkarıldı';
        aktifOda.uyeler.delete(hedef.id);
        hedef.aktifOda = null;
        olayiLogla('KICK', kullanici, aktifOda.ad, `${hedef.kullaniciAdi} atıldı: ${sebep}`);
        odayaDuyur(aktifOda, sistemMesajiFormatla(`\x1b[1;31m${hedef.kullaniciAdi} odadan atıldı (${sebep}).\x1b[0m`));
        hedef.mesajGonder(sistemMesajiFormatla(`\x1b[1;31m${aktifOda.ad} odasından atıldınız: ${sebep}\x1b[0m`));
        break;
      }

      case 'away': {
        const mesaj = parametreler.join(' ');
        if (!mesaj) {
          if (kullanici.uzaktaMesaji) {
            kullanici.uzaktaMesaji = null;
            kullanici.mesajGonder(sistemMesajiFormatla('Uzakta modu kapatıldı (Geri döndünüz).'));
          } else {
            kullanici.mesajGonder(sistemMesajiFormatla('Kullanım: /away <mesaj> (Kapatmak için sadece /away yazın)'));
          }
        } else {
          kullanici.uzaktaMesaji = mesaj;
          kullanici.mesajGonder(sistemMesajiFormatla(`\x1b[33mUzakta modu aktif edildi:\x1b[0m ${mesaj}`));
        }
        break;
      }

      case 'msg':
      case 'm':
      case 'reply':
      case 'r': {
        const hizliCevapMi = komut === 'reply' || komut === 'r';
        const ozelMesajMetni = hizliCevapMi ? parametreler.join(' ') : parametreler.slice(1).join(' ');

        let aliciKullanici = null;
        if (hizliCevapMi) {
          if (!kullanici.sonMesajlasilanId) {
            return kullanici.mesajGonder(sistemMesajiFormatla('Yanıtlanabilecek etkin bir konuşma yok.'));
          }
          aliciKullanici = kullanicilar.get(kullanici.sonMesajlasilanId);
          if (!aliciKullanici) {
            return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31m-!- Konuştuğunuz kullanıcının oturumu kapandı, yanıt teslim edilemedi.\x1b[0m'));
          }
        } else {
          aliciKullanici = kullaniciBul(parametreler[0]);
        }

        if (!aliciKullanici || !ozelMesajMetni) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mKullanım: /msg <kullaniciAdi> <mesaj>\x1b[0m'));
        }

        kullanici.sonMesajlasilanId = aliciKullanici.id;
        aliciKullanici.sonMesajlasilanId = kullanici.id;

        olayiLogla('OZEL_MESAJ', kullanici, `@${aliciKullanici.kullaniciAdi}`, ozelMesajMetni);
        kullanici.mesajGonder(`\x1b[90m[${suAnkiSaat()}]\x1b[0m \x1b[35m[msg -> ${aliciKullanici.kullaniciAdi}]\x1b[0m ${ozelMesajMetni}`);
        if (aliciKullanici.id !== kullanici.id) {
          aliciKullanici.mesajGonder(`\x07\x1b[90m[${suAnkiSaat()}]\x1b[0m \x1b[1;35m[${kullanici.kullaniciAdi} -> sana]\x1b[0m ${ozelMesajMetni}`);
          if (aliciKullanici.uzaktaMesaji) {
            kullanici.mesajGonder(sistemMesajiFormatla(`\x1b[33m[UZAKTA] ${aliciKullanici.kullaniciAdi} şu an uzakta: ${aliciKullanici.uzaktaMesaji}\x1b[0m`));
          }
        }
        break;
      }

      case 'key': {
        if (!kullanici.aktifOda) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mHerhangi bir odada değilsiniz.\x1b[0m'));
        }
        const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
        if (!aktifOda || !aktifOda.uyeler.has(kullanici.id)) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu odanın üyesi değilsiniz.\x1b[0m'));
        }
        if (aktifOda.yoneticiId !== kullanici.id) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mSadece oda yöneticisi (@) şifre değiştirebilir.\x1b[0m'));
        }
        aktifOda.sifre = parametreler[0] || '';
        olayiLogla('ODA_SIFRESI', kullanici, aktifOda.ad, aktifOda.sifre ? 'Oda şifrelendi' : 'Oda şifresi kaldırıldı');
        odayaDuyur(aktifOda, sistemMesajiFormatla(`Oda şifresi ${aktifOda.sifre ? 'AKTİF EDİLDİ (+k)' : 'KALDIRILDI (-k)'}`));
        break;
      }

      case 'secret': {
        if (!kullanici.aktifOda) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mHerhangi bir odada değilsiniz.\x1b[0m'));
        }
        const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
        if (!aktifOda || !aktifOda.uyeler.has(kullanici.id)) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu odanın üyesi değilsiniz.\x1b[0m'));
        }
        if (aktifOda.yoneticiId !== kullanici.id) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mSadece oda yöneticisi (@) gizli modu değiştirebilir.\x1b[0m'));
        }
        aktifOda.gizliMi = !aktifOda.gizliMi;
        olayiLogla('GIZLI_ODA', kullanici, aktifOda.ad, `Gizli mod: ${aktifOda.gizliMi}`);
        odayaDuyur(aktifOda, sistemMesajiFormatla(`Gizli oda modu: ${aktifOda.gizliMi ? 'AÇIK (+s)' : 'KAPALI (-s)'}`));
        break;
      }

      case 'who': {
        if (!kullanici.aktifOda) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mHerhangi bir odaya üye değilsiniz.\x1b[0m'));
        }
        const aktifOda = odalar.get(kullanici.aktifOda.toLowerCase());
        if (!aktifOda || !aktifOda.uyeler.has(kullanici.id)) {
          return kullanici.mesajGonder(sistemMesajiFormatla('\x1b[1;31mBu odanın üye listesini göremezsiniz.\x1b[0m'));
        }
        const isimler = [...aktifOda.uyeler]
          .map((id) => {
            const uye = kullanicilar.get(id);
            return uye ? (aktifOda.yoneticiId === id ? `@${uye.kullaniciAdi}` : uye.kullaniciAdi) : '';
          })
          .filter(Boolean)
          .join(', ');
        kullanici.mesajGonder(sistemMesajiFormatla(`Odadaki kişiler (${aktifOda.ad}): ${isimler}`));
        break;
      }

      case 'list':
        for (const oda of odalar.values()) {
          if (!oda.gizliMi || oda.uyeler.has(kullanici.id)) {
            const kilitBilgisi = oda.sifre ? '[Şifreli]' : '[Açık]';
            const baslikBilgisi = oda.baslik ? ` - "${oda.baslik}"` : '';
            kullanici.mesajGonder(sistemMesajiFormatla(`${oda.ad} (${oda.uyeler.size} kişi) ${kilitBilgisi}${baslikBilgisi}`));
          }
        }
        break;

      case 'clear':
      case 'c':
        kullanici.mesajGonder('\x1b[2J\x1b[H');
        break;

      case 'quit':
      case 'q':
        kullanici.baglantiyiKapat();
        break;

      case 'help':
        kullanici.mesajGonder(sistemMesajiFormatla('Komutlar: /join <#oda> [şifre] | /msg <kisi> <mesaj> | /reply <mesaj> | /nick <ad> | /me <eylem> | /topic [konu] | /kick <kisi> [sebep] | /away [mesaj] | /key [şifre] | /secret | /who | /list | /clear | /quit'));
        break;

      default:
        kullanici.mesajGonder(sistemMesajiFormatla(`Bilinmeyen komut: /${komut} (Yardım için /help yazın)`));
        break;
    }
  }

  // ==========================================================================
  // SUNUCU 1: SSH ARAYÜZÜ (Port: 2222)
  // ==========================================================================
  const sshSunucusu = new SSHServer({ hostKeys: [sshSunucuAnahtariAl()] }, (sshIstemci, baglantiBilgisi) => {
    const istemciIp = baglantiBilgisi.ip;

    if (sayacArtir(aktifSshSoketleri, istemciIp) > IP_BASINA_MAKS_BAGLANTI) {
      sayacAzalt(aktifSshSoketleri, istemciIp);
      return sshIstemci.end();
    }

    let sayacTemizlendi = false;
    function sayacTemizle() {
      if (!sayacTemizlendi) {
        sayacTemizlendi = true;
        sayacAzalt(aktifSshSoketleri, istemciIp);
      }
    }

    let authTamamlandi = false;
    const authZamanAsimi = setTimeout(() => {
      if (!authTamamlandi) {
        try { sshIstemci.end(); } catch {}
      }
    }, KIMLIK_DOGRULAMA_ZAMAN_ASIMI_MS);

    let secilenIsim = 'samsepi0l';

    sshIstemci.on('authentication', (kimlik) => {
      const hamKullaniciAdi = String(kimlik.username || '').trim();
      const kucukAd = hamKullaniciAdi.toLowerCase();

      if (sshAnahtarlari.has(kucukAd)) {
        const kayit = sshAnahtarlari.get(kucukAd);

        if (kimlik.method !== 'publickey' || !kimlik.key || !kimlik.key.data) {
          return kimlik.reject(['publickey']);
        }

        if (!kayit.key.getPublicSSH().equals(kimlik.key.data)) {
          return kimlik.reject(['publickey']);
        }

        if (!kimlik.signature) {
          return kimlik.accept();
        }

        if (kayit.key.verify(kimlik.blob, kimlik.signature, kimlik.hashAlgo) !== true) {
          return kimlik.reject(['publickey']);
        }

        secilenIsim = kayit.originalName;
        authTamamlandi = true;
        clearTimeout(authZamanAsimi);
        return kimlik.accept();
      }

      if (AYRILMIS_ISIMLER.has(kucukAd)) {
        return kimlik.reject(['publickey', 'password']);
      }

      if (kimlik.method === 'publickey') {
        if (!kimlik.signature) {
          return kimlik.accept();
        }
        secilenIsim = hamKullaniciAdi;
        authTamamlandi = true;
        clearTimeout(authZamanAsimi);
        return kimlik.accept();
      }

      if (kimlik.method === 'none' || kimlik.method === 'password') {
        secilenIsim = hamKullaniciAdi || 'misafir';
        authTamamlandi = true;
        clearTimeout(authZamanAsimi);
        return kimlik.accept();
      }

      return kimlik.reject(['publickey', 'password', 'none']);
    });

    sshIstemci.on('ready', () => {
      authTamamlandi = true;
      clearTimeout(authZamanAsimi);

      sshIstemci.on('session', (oturumuKabulEt) => {
        const oturum = oturumuKabulEt();
        oturum.on('pty', (ptyKabulEt) => ptyKabulEt && ptyKabulEt());

        oturum.on('shell', (kabuguKabulEt) => {
          const akis = kabuguKabulEt();

          let aktifKullanici = null;
          let kapandiMi = false;

          // Tab ile Otomatik Komut ve Takma Ad Tamamlama
          function komutVeyaNickTamamla(satir) {
            const komutlar = [
              '/join', '/msg', '/reply', '/nick', '/me', '/topic', '/kick', '/away',
              '/key', '/secret', '/who', '/list', '/clear', '/help', '/quit'
            ];

            if (satir.startsWith('/') && !satir.includes(' ')) {
              const eslesenler = komutlar.filter((k) => k.startsWith(satir.toLowerCase()));
              return [eslesenler.length ? eslesenler : komutlar, satir];
            }

            const kelimeler = satir.split(' ');
            const sonKelime = kelimeler[kelimeler.length - 1];
            if (!sonKelime) return [[], satir];

            const nickler = [];
            if (aktifKullanici && aktifKullanici.aktifOda) {
              const aktifOda = odalar.get(aktifKullanici.aktifOda.toLowerCase());
              if (aktifOda) {
                for (const uyeId of aktifOda.uyeler) {
                  const u = kullanicilar.get(uyeId);
                  if (u && u.id !== aktifKullanici.id) nickler.push(u.kullaniciAdi);
                }
              }
            }
            for (const u of kullanicilar.values()) {
              if (u.id !== aktifKullanici?.id && !nickler.includes(u.kullaniciAdi)) {
                nickler.push(u.kullaniciAdi);
              }
            }

            const eslesenNickler = nickler.filter((n) => n.toLowerCase().startsWith(sonKelime.toLowerCase()));
            return [eslesenNickler, sonKelime];
          }

          const klavye = readline.createInterface({
            input: akis,
            output: akis,
            terminal: true,
            completer: komutVeyaNickTamamla
          });

          function guvenliKapat() {
            if (kapandiMi) return;
            kapandiMi = true;
            sayacTemizle();
            kullaniciCikar(aktifKullanici);
            try { klavye.close(); } catch {}
            try { akis.end(); } catch {}
            try { sshIstemci.end(); } catch {}
          }

          aktifKullanici = kullaniciKaydet({
            kullaniciAdi: secilenIsim,
            ip: baglantiBilgisi.ip,
            port: baglantiBilgisi.port,
            baglantiTuru: 'SSH',
            mesajGonder: (metin) => {
              if (kapandiMi || klavye.closed || !akis.writable || akis.destroyed) return;
              akis.write(`\r\x1b[2K${metin}\r\n`);
              klavye.setPrompt(`\x1b[36m[(${aktifKullanici?.aktifOda || 'lobi'})] > \x1b[0m`);
              klavye.prompt(true);
            },
            baglantiyiKapat: guvenliKapat
          });

          klavye.on('line', (satir) => {
            if (kapandiMi || klavye.closed) return;
            if (akis.writable) {
              akis.write('\x1b[1A\r\x1b[2K');
            }
            mesajVeyaKomutIsle(aktifKullanici, satir);
          });

          klavye.on('close', guvenliKapat);
          akis.on('close', guvenliKapat);
          akis.on('end', guvenliKapat);
          sshIstemci.on('close', guvenliKapat);
          sshIstemci.on('end', guvenliKapat);
        });
      });
    });

    sshIstemci.on('close', sayacTemizle);
    sshIstemci.on('end', sayacTemizle);
    sshIstemci.on('error', sayacTemizle);
  });

  // ==========================================================================
  // SUNUCU 2: TLS İSTEMCİ ARAYÜZÜ (Port: 6697)
  // ==========================================================================
  let tlsAyarlari;
  try {
    tlsAyarlari = tlsSertifikasiAl();
  } catch {
    tlsAyarlari = { key: sshSunucuAnahtariAl(), cert: sshSunucuAnahtariAl() };
  }

  const istemciSunucusu = tls.createServer(tlsAyarlari, (soket) => {
    const istemciIp = soket.remoteAddress;

    if (sayacArtir(aktifTlsSoketleri, istemciIp) > IP_BASINA_MAKS_BAGLANTI) {
      sayacAzalt(aktifTlsSoketleri, istemciIp);
      return soket.destroy();
    }

    let sayacTemizlendi = false;
    function sayacTemizle() {
      if (!sayacTemizlendi) {
        sayacTemizlendi = true;
        sayacAzalt(aktifTlsSoketleri, istemciIp);
      }
    }

    let authTamamlandi = false;
    const authZamanAsimi = setTimeout(() => {
      if (!authTamamlandi) {
        try { soket.destroy(); } catch {}
      }
    }, KIMLIK_DOGRULAMA_ZAMAN_ASIMI_MS);

    let aktifKullanici = null;
    let gelenVeriTamponu = '';

    soket.on('data', (parca) => {
      gelenVeriTamponu += parca.toString('utf8');

      if (gelenVeriTamponu.length > MAKS_GELEN_VERI_BOYUTU) {
        return soket.destroy();
      }

      const satirlar = gelenVeriTamponu.split('\n');
      gelenVeriTamponu = satirlar.pop();

      for (const satir of satirlar) {
        if (!satir.trim()) continue;

        let veri = null;
        try {
          veri = JSON.parse(satir);
        } catch {
          return soket.destroy();
        }

        if (!aktifKullanici) {
          const istenenNick = String(veri.kullaniciAdi || '').trim();
          const kucukNick = istenenNick.toLowerCase();

          if (sshAnahtarlari.has(kucukNick) || AYRILMIS_ISIMLER.has(kucukNick)) {
            if (soket.writable) {
              soket.write(JSON.stringify({
                hata: true,
                metin: '\x1b[1;31m-!- Bu isim kayıtlıdır ve yalnızca SSH anahtarı ile kullanılabilir.\x1b[0m'
              }) + '\n');
            }
            return soket.destroy();
          }

          authTamamlandi = true;
          clearTimeout(authZamanAsimi);

          aktifKullanici = kullaniciKaydet({
            kullaniciAdi: istenenNick || 'istemci',
            ip: soket.remoteAddress,
            port: soket.remotePort,
            baglantiTuru: 'CLIENT-TLS',
            mesajGonder: (metin) => {
              if (soket.writable) {
                soket.write(JSON.stringify({ metin }) + '\n');
              }
            },
            baglantiyiKapat: () => soket.end()
          });
        } else if (veri.metin) {
          mesajVeyaKomutIsle(aktifKullanici, veri.metin);
        }
      }
    });

    soket.on('close', () => {
      sayacTemizle();
      kullaniciCikar(aktifKullanici);
    });
    soket.on('error', () => {
      sayacTemizle();
      kullaniciCikar(aktifKullanici);
    });
  });

  function baslat(sshPort = AYARLAR.SSH_PORT, clientPort = AYARLAR.CLIENT_PORT) {
    return Promise.all([
      new Promise((tamam, hata) => {
        sshSunucusu.once('error', hata);
        sshSunucusu.listen(sshPort, '0.0.0.0', () => tamam(sshSunucusu.address().port));
      }),
      new Promise((tamam, hata) => {
        istemciSunucusu.once('error', hata);
        istemciSunucusu.listen(clientPort, '0.0.0.0', () => tamam(istemciSunucusu.address().port));
      })
    ]).then(([acilanSshPort, acilanClientPort]) => ({
      sshPort: acilanSshPort,
      clientPort: acilanClientPort
    }));
  }

  function durdur() {
    return Promise.all([
      new Promise((tamam) => sshSunucusu.close(tamam)),
      new Promise((tamam) => istemciSunucusu.close(tamam))
    ]);
  }

  return { baslat, durdur, kullanicilar, odalar };
}

if (require.main === module) {
  sunucuOlustur()
    .baslat()
    .then(({ sshPort, clientPort }) => {
      console.log('\x1b[1;32m[SHADOWLINE SOHBET SUNUCUSU AKTİF]\x1b[0m');
      console.log(`  1) SSH ile bağlan     : ssh samsepi0l@127.0.0.1 -p ${sshPort}`);
      console.log(`  2) İstemci ile bağlan : npm run client -- d0loresH4ze 127.0.0.1 ${clientPort}`);
      console.log(`  3) Logları oku        : npm run logs`);
    })
    .catch((err) => {
      console.error('Sunucu başlatılamadı:', err);
      process.exit(1);
    });
}

module.exports = { sunucuOlustur };
