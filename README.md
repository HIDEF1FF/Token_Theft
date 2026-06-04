Silent Infiltration

Der Quelltext Program.cs ist der Quelltext zum Buch (ohne Kernel unhook implementation):
(pe.cs ist die Ausgangsquelltext wird nicht gebraucht, dient nur für Archivierung)

Öffne PowerShell als Administrator.

Führe aus:

powershell
.\add_AssignPrimaryTokenPrivilege.ps1
Optional mit anderem Benutzernamen:

powershell
.\add_AssignPrimaryTokenPrivilege.ps1 -UserName "DOMAIN\Benutzer"
Starte den PC neu (das Skript fragt danach).

Was das Skript macht
Exportiert die aktuelle Sicherheitsrichtlinie (User Rights Assignment).

Sucht die Zeile SeAssignPrimaryTokenPrivilege und fügt die SID des angegebenen Benutzers hinzu (im Format *S-1-5-...).

Falls die Zeile nicht existiert, wird sie neu angelegt.

Importiert die geänderte Richtlinie zurück.

Fordert einen Neustart an.

Nach dem Neustart
Dein Benutzer besitzt dann SeAssignPrimaryTokenPrivilege. Danach funktioniert dein ursprünglicher C#-Code mit CreateProcessAsUser problemlos – du bekommst eine echte SYSTEM-Shell.

Sicherheitshinweis: Dieses Privileg sollte nur zu Testzwecken in isolierten Umgebungen erteilt werden, da es eine komplette Übernahme des Systems ermöglicht.

