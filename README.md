Silent Infiltration

Der Quelltext Program.cs ist der Quelltext zum Buch (ohne Kernel unhook implementation):


Einfache manuelle Lösung für die Funktion des Programms erforderliche Rechtevergabe (funktioniert garantiert)
Führe diese CMD-Befehle als Administrator aus (nicht PowerShell):

:: 1. Stoppe den Security-Account-Manager Dienst (kurzzeitig)
net stop samss

:: 2. Lösche die beschädigte Datenbank
del /f /q %windir%\security\database\secedit.sdb

:: 3. Erstelle eine neue Datenbank aus der Standardvorlage
secedit /configure /cfg %windir%\inf\defltbase.inf /db %windir%\security\database\secedit.sdb

:: 4. Starte den Dienst neu
net start samss

Dann das Privileg auf einem anderen Weg hinzufügen (Registry)
cmd


:: 1. Exportiere die aktuelle Richtlinie
secedit /export /cfg %temp%\secpol.inf

:: 2. Öffne die Datei
notepad %temp%\secpol.inf

In Notepad:

Suche nach [Privilege Rights] (ohne die Anführungszeichen)

Darunter sollte SeAssignPrimaryTokenPrivilege stehen

Wenn nicht vorhanden, füge unter [Privilege Rights] diese Zeile ein:

text:  Die SID ist maschinenabhängig
SeAssignPrimaryTokenPrivilege = SID (Bsp.: bei mir *S-1-5-21-2963405314-4200755379-1400371717-1001)
Speichern und schließen

cmd

:: 3. Importiere die Richtlinie
secedit /configure /db %temp%\secedit.sdb /cfg %temp%\secpol.inf /areas USER_RIGHTS

:: 4. Direkter Registry-Eintrag (Fallback)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Secedit\Privileges" /v "SeAssignPrimaryTokenPrivilege" /t REG_SZ /d "*S-1-5-21-2963405314-4200755379-1400371717-1001" /f


Neustart
cmd

shutdown /r /t 0
Nach dem Neustart prüfen:
cmd
whoami /priv | findstr AssignPrimaryToken



Das Problem: Die SID ist maschinenabhängig
Die SID, die du dir notiert hast, besteht aus zwei Teilen:

Präfix (S-1-5-21-2963405314-4200755379-1400371717): Das ist die Maschinen-SID. Sie ist ein eindeutiger Wert, den Windows bei der Installation generiert. Dieser ist auf jedem Computer anders.

Suffix (-1001): Das ist die Relative ID (RID). Bei lokalen Benutzern ist diese Zahl meistens konsistent (z.B. 1000 für den ersten lokalen Admin, 1001 für den nächsten).

Die Konsequenz: Die spezifische SID, die du hast, existiert nur auf deinem aktuellen Rechner. Auf einem anderen Rechner hat ein Benutzer (selbst wenn er denselben Namen hat) eine andere, eindeutige SID.

Die Lösung: Die SID auf einem anderen Rechner dynamisch ermitteln
Anstatt eine feste ID zu verwenden (was nicht funktionieren würde), musst du in deinem Code oder Skript die SID des Zielbenutzers auf dem Zielrechner zur Laufzeit abfragen. Hier sind die standardisierten Wege dafür:

1. Die PowerShell-Methode (Am vielseitigsten)
Das Cmdlet Get-LocalUser ist der moderne Standard, um lokale Benutzer auszulesen. Um die SID für einen bestimmten Benutzernamen zu erhalten, verwendest du:

powershell
(Get-LocalUser -Name "DER_BENUTZERNAME").Sid.Value
Ersetze "DER_BENUTZERNAME" durch den tatsächlichen Benutzernamen, den du suchst.

Beispiel: Für den Benutzer testuser würde der Befehl so aussehen und die zugehörige SID ausgeben.

powershell
(Get-LocalUser -Name "testuser").Sid.Value
2. Die klassische WMIC-Methode (Für ältere Systeme)
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
