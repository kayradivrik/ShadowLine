using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace ShadowLineClient
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        const int STD_OUTPUT_HANDLE = -11;
        const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;

        static void EnableAnsiColors()
        {
            try
            {
                IntPtr handle = GetStdHandle(STD_OUTPUT_HANDLE);
                uint mode;
                if (GetConsoleMode(handle, out mode))
                {
                    SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }
            catch { }
        }

        static void Main(string[] args)
        {
            Console.Title = "ShadowLine - Secure Terminal Chat";
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;
            EnableAnsiColors();

            Console.WriteLine("\x1b[1;36m========================================================\x1b[0m");
            Console.WriteLine("\x1b[1;32m       SHADOWLINE - GÜVENLİ SOHBET İSTEMCİSİ            \x1b[0m");
            Console.WriteLine("\x1b[1;36m========================================================\x1b[0m\n");

            // 1. Takma Ad Al
            Console.Write("\x1b[1;37m[?] Takma Adınız (Nick) \x1b[90m[Varsayılan: Hazal]\x1b[1;37m: \x1b[0m");
            string nick = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(nick)) nick = "Hazal";

            // 2. Sunucu IP Al
            Console.Write("\x1b[1;37m[?] Sunucu IP Adresi \x1b[90m[Varsayılan: 82.153.241.173]\x1b[1;37m: \x1b[0m");
            string ip = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(ip)) ip = "82.153.241.173";

            // 3. Sunucu Portu
            int port = 6697;

            // 4. Sunucu Şifresi Al
            Console.Write("\x1b[1;37m[?] Sunucu Giriş Şifresi \x1b[90m[Varsayılan: gamerfilo7]\x1b[1;37m: \x1b[0m");
            string pass = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(pass)) pass = "gamerfilo7";

            Console.WriteLine(string.Format("\n\x1b[33m[*] {0}:{1} adresine TLS ile bağlanılıyor...\x1b[0m", ip, port));

            try
            {
                TcpClient tcp = new TcpClient();
                tcp.Connect(ip, port);

                SslStream ssl = new SslStream(
                    tcp.GetStream(),
                    false,
                    new RemoteCertificateValidationCallback((s, cert, chain, err) => true)
                );

                ssl.AuthenticateAsClient(ip);
                Console.WriteLine("\x1b[1;32m[+] TLS Güvenli Bağlantı Kuruldu!\x1b[0m\n");

                StreamReader reader = new StreamReader(ssl, Encoding.UTF8);
                StreamWriter writer = new StreamWriter(ssl, new UTF8Encoding(false)) { AutoFlush = true };

                // Giriş Paketini Gönder
                string girisJson = string.Format("{{\"kullaniciAdi\":\"{0}\",\"sifre\":\"{1}\"}}", EscapeJson(nick), EscapeJson(pass));
                writer.WriteLine(girisJson);

                bool calisiyor = true;

                // Gelen Mesajları Okuyan Arka Plan İş Parçacığı
                Thread okuyucuThread = new Thread(() =>
                {
                    try
                    {
                        string line;
                        while (calisiyor && (line = reader.ReadLine()) != null)
                        {
                            if (string.IsNullOrWhiteSpace(line)) continue;

                            string metin = AyiklaMetin(line);
                            if (!string.IsNullOrEmpty(metin))
                            {
                                Console.Write("\r\x1b[2K");
                                Console.WriteLine(metin);
                                Console.Write("\x1b[1;36m[ShadowLine] > \x1b[0m");
                            }
                        }
                    }
                    catch
                    {
                        if (calisiyor)
                        {
                            Console.WriteLine("\n\x1b[1;31m-!- Sunucu bağlantısı kapandı.\x1b[0m");
                        }
                    }
                });
                okuyucuThread.IsBackground = true;
                okuyucuThread.Start();

                // Kullanıcı Girişi Döngüsü
                while (calisiyor && tcp.Connected)
                {
                    string input = Console.ReadLine();
                    if (input == null) break;

                    string temiz = input.Trim();
                    if (temiz.Equals("/quit", StringComparison.OrdinalIgnoreCase) || temiz.Equals("/q", StringComparison.OrdinalIgnoreCase))
                    {
                        calisiyor = false;
                        break;
                    }

                    if (!string.IsNullOrEmpty(temiz))
                    {
                        try
                        {
                            Console.Write("\x1b[1A\r\x1b[2K");
                            string paket = string.Format("{{\"metin\":\"{0}\"}}", EscapeJson(temiz));
                            writer.WriteLine(paket);
                        }
                        catch
                        {
                            break;
                        }
                    }
                }

                calisiyor = false;
                try { ssl.Close(); } catch { }
                try { tcp.Close(); } catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine(string.Format("\n\x1b[1;31m[HATA] Bağlantı kurulamadı:\x1b[0m {0}", ex.Message));
            }

            Console.WriteLine("\nÇıkmak için Enter'a basın...");
            Console.ReadLine();
        }

        static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "");
        }

        static string AyiklaMetin(string json)
        {
            try
            {
                int idx = json.IndexOf("\"metin\":");
                if (idx < 0) return null;
                int start = json.IndexOf("\"", idx + 8);
                if (start < 0) return null;

                StringBuilder sb = new StringBuilder();
                bool escape = false;
                for (int i = start + 1; i < json.Length; i++)
                {
                    char c = json[i];
                    if (escape)
                    {
                        if (c == 'n') sb.Append('\n');
                        else if (c == 'r') sb.Append('\r');
                        else if (c == 't') sb.Append('\t');
                        else if (c == 'u' && i + 4 < json.Length)
                        {
                            string hex = json.Substring(i + 1, 4);
                            int code;
                            if (int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out code))
                            {
                                sb.Append((char)code);
                                i += 4;
                            }
                        }
                        else sb.Append(c);
                        escape = false;
                    }
                    else if (c == '\\')
                    {
                        escape = true;
                    }
                    else if (c == '\"')
                    {
                        break;
                    }
                    else
                    {
                        sb.Append(c);
                    }
                }
                return sb.ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}
