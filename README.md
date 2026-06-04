Silent Infiltration

Der Quelltext Program.cs ist der Quelltext zum Buch (ohne Kernel unhook implementation):
(pe.cs ist die Ausgangsquelltext wird nicht gebraucht, dient nur für Archivierung)


Einfache manuelle Lösung (funktioniert garantiert)
Führe diese CMD-Befehle als Administrator aus (nicht PowerShell):

cmd
cd %temp%

:: 1. Exportiere die Richtlinie
secedit /export /cfg secpol_original.inf /areas USER_RIGHTS

:: 2. Kopiere die Datei
copy secpol_original.inf secpol_modified.inf

:: 3. Öffne die Datei zum Bearbeiten
notepad secpol_modified.inf
In Notepad:

Suche nach SeAssignPrimaryTokenPrivilege

Du findest eine Zeile wie:
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20,...

Füge am Ende der Zeile deine SID hinzu (Tippe ein Komma und dann deine SID):
,*S-1-5-21-2963405314-4200755379-1400371717-1001

Die Zeile sollte dann so aussehen:
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20,...,*S-1-5-21-2963405314-4200755379-1400371717-1001

Speichern (Strg+S) und Notepad schließen

Dann importieren:

cmd
:: 4. Importiere die geänderte Datei
secedit /configure /db secedit.sdb /cfg secpol_modified.inf /areas USER_RIGHTS /log secedit.log

:: 5. Erfolg prüfen
if %errorlevel% equ 0 (echo Erfolg) else (echo Fehler - siehe Log)
Wenn das auch nicht funktioniert: Komplette Neuaufsetzung
Manchmal ist die secedit-Datenbank korrupt. Dann hilft nur noch:

cmd
:: 1. Datenbank löschen
del /f /q %windir%\security\database\secedit.sdb

:: 2. Neue Datenbank aus Vorlage erstellen
secedit /configure /cfg %windir%\inf\defltbase.inf /db secedit.sdb

:: 3. Jetzt wieder den obigen Export/Import-Versuch starten
