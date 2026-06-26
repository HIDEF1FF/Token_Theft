Silent Infiltration (Windows 64Bit)


Im Ordner HellsGate_System_admin_Console ist der Quellcode zu meinem ersten Buch Silent Infiltration - Hells Gate
Themen: HellsGate (Direct Syscall), Stack Spoofing (gegen Stackwalk) , TextProtector unhooking, EDR Silence

Im Ordner Ordner Final_HellsHall_2026_06_26  befindet sich das Project zum Buch Silent Infiltration - HellsHall 
Themen: Reflective DLL Injection mit TokenTheft als Payload mit Rechteerweiterung und diversen Stealth mechanismen mit HellsHall (indirect syscall) und GateKeeper  



**********************************************************************************************************************************************
Einfache manuelle Lösung für die Funktion des Programms erforderliche Rechtevergabe (funktioniert garantiert) powershell mit adminrechten

1_priv_erzwingen.ps1  (erzwing dieses Recht : SeAssignPrimaryTokenPrivilege) 


Neustart
cmd

shutdown /r /t 0
Nach dem Neustart prüfen:
cmd
whoami /priv | findstr AssignPrimaryToken



**********************************************************************************************************************************************
Das Problem: Die SID ist maschinenabhängig

powershell
(Get-LocalUser -Name "DER_BENUTZERNAME").Sid.Value
Ersetze "DER_BENUTZERNAME" durch den tatsächlichen Benutzernamen, den du suchst.

Beispiel: Für den Benutzer testuser würde der Befehl so aussehen und die zugehörige SID ausgeben.

powershell
(Get-LocalUser -Name "testuser").Sid.Value
2. Die klassische WMIC-Methode (Für ältere Systeme)


**********************************************************************************************************************************************
Falls du mit einem älteren Windows-System arbeitest oder kein PowerShell verwenden kannst, ist das Kommandozeilentool wmic eine Alternative:

cmd
wmic useraccount where name='DER_BENUTZERNAME' get sid
3. Die Whoami-Methode (Für den aktuell angemeldeten Benutzer)
Wenn du nur die SID des Benutzers brauchst, der gerade eingeloggt ist, ist whoami die schnellste Methode:

cmd
whoami /user
Hintergrund: Was ist SeAssignPrimaryTokenPrivilege?
Um dein Verständnis abzurunden: Der lange String, den du erwähnt hast, ist ein Benutzer-SID. Das zugehörige SeAssignPrimaryTokenPrivilege ist ein Benutzerrecht (User Right).

Bedeutung: Dieses Recht ist technisch notwendig, um einem neuen Prozess das Token eines anderen Benutzers zuzuweisen (z.B. wenn du eine cmd.exe mit SYSTEM-Rechten startest).

Anwendung: Dein Skript oder Programm muss mit einem Konto laufen, dem dieses Recht gewährt wurde (meist das SYSTEM-Konto oder ein Administrator mit entsprechenden Local Security Policy-Einstellungen), sonst schlägt der Vorgang fehl.

Fazit für dein Projekt
Hartkodiere niemals eine Benutzer-SID, da sie nicht portabel ist.

Verwende die PowerShell oder WMIC-Befehle in deinem Tool, um die SID des gewünschten Zielbenutzers auf dem aktuellen System dynamisch zu ermitteln.

Stelle sicher, dass dein Code mit den notwendigen Rechten läuft, um das SeAssignPrimaryTokenPrivilege effektiv nutzen zu können.












