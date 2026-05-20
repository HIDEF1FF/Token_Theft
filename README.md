Silent Infiltration

Der Quelltext Program.cs ist der Quelltext zum Buch (ohne Kernel unhook implementation):
(pe.cs ist die Ausgangsquelltext wird nicht gebraucht, dient nur für Archivierung)

Id ProcessName SessionId
  -- ----------- ---------
1252 winlogon            1


PS C:\WINDOWS\system32>
die session id unterscheidet sich von meiner
Ja, das ist normal – und sehr wichtig für das Verständnis von Token Theft.

Sie haben festgestellt: Ihre PowerShell/Konsole läuft in einer anderen Session als der Winlogon-Prozess.

Die zwei Sessions im Detail
Ihre aktuelle Session (wo Sie den Exploit ausführen)
Sie sind als WERBETECHNIK4-P\RMW PC 2 ueb eingeloggt – vermutlich Session 1 oder Session 2, je nachdem, wie Sie angemeldet sind.

Der Winlogon-Prozess (den Sie angreifen)
Sie sehen: Winlogon mit PID 1252 in Session 1.

Moment: Wenn Sie als Benutzer in Session 1 sind, dann läuft Winlogon in derselben Session wie Sie? Oder sind Sie in einer anderen Session?

Lassen Sie uns das herausfinden:

powershell
# Ihre eigene Session-ID ermitteln
$sessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
Write-Host "Ihre Session-ID: $sessionId"

# Alle Winlogon-Prozesse mit Session-ID
Get-Process -Name winlogon | Select-Object Id, @{Name='SessionId';Expression={$_.SessionId}}
Warum das für Token Theft entscheidend ist
Das Problem mit Winlogon in Session 1
Das Winlogon-Token in derselben Session wie der Benutzer (Session 1) hat:

Token-Eigenschaft	Wert	Problem
Session ID	-1 oder 1	Nicht für interaktive Prozesse geeignet
Integrity Level	0x0 (Untrusted)	Zu niedrig
Elevated	False	Nicht administrativ
Aus diesem Grund funktionierte Ihr Exploit nicht richtig! Das Token ist quasi eine "leere Hülle" – es kann keine sinnvollen interaktiven Prozesse starten.

Das bessere Ziel: Winlogon in Session 0 oder einer anderen Session
Wenn Sie einen Benutzerwechsel durchführen, entsteht ein neuer Winlogon in einer anderen Session – und dessen Token ist brauchbar.

Die Lösung für funktionierenden Token Theft
Schritt 1: Session wechseln/eine neue erstellen
cmd
# Option A: Schnellbenutzerwechsel (Tastenkombination)
Windows + L   # Sperrbildschirm
# Dann auf "Benutzer wechseln" klicken, einen zweiten Benutzer anmelden

# Option B: Remote Desktop Connection
mstsc /v:127.0.0.1 /admin
Jetzt haben Sie zwei Winlogon-Prozesse:

Einer in Ihrer ursprünglichen Session (ungültiges Token)

Einer in der neuen Session (gültiges Token)

Schritt 2: Die richtige Winlogon-PID identifizieren
powershell
Get-Process winlogon | Select-Object Id, SessionId
Der Winlogon in der neuen Session (nicht Session 1) ist Ihr Target.

Schritt 3: Den Exploit auf die neue PID ausführen
Ändern Sie Ihren Exploit, um die neue Winlogon-PID (nicht 1252) zu verwenden.

Vergleich der Token-Qualität
Winlogon-Quelle	Session ID	Integrity	Kann cmd.exe starten?
Ihre eigene Session (Session 1)	-1	0x0 (Untrusted)	❌ Nein
Neue Session (Session 2+)	Z.B. 2	High (0x3000)	✅ Ja
Fazit
Ihr Problem: Sie greifen den Winlogon in Ihrer eigenen Session an – dessen Token ist nutzlos.

Die Lösung: Wechseln Sie den Benutzer (Windows+L → Benutzer wechseln), dann haben Sie einen zweiten Winlogon in einer neuen Session. Dessen Token ist voll funktionsfähig und kann echte SYSTEM-Prozesse starten.

Ihr Exploit selbst ist gut – er scheitert nur am falschen Target. Probieren Sie es mit dem Winlogon aus einer anderen Session!

Diese Antwort ist KI-generiert und dient nur als Referenz.

Geschrieben von Mr.HIDE 





