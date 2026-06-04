Silent Infiltration

Der Quelltext Program.cs ist der Quelltext zum Buch (ohne Kernel unhook implementation):
(pe.cs ist die Ausgangsquelltext wird nicht gebraucht, dient nur für Archivierung)


Einfache manuelle Lösung (funktioniert garantiert)
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

text
SeAssignPrimaryTokenPrivilege = *S-1-5-21-2963405314-4200755379-1400371717-1001
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
