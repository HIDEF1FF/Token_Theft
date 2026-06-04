# add_AssignPrimaryTokenPrivilege.ps1
# Führt den aktuellen Benutzer (oder einen angegebenen) zur Richtlinie "SeAssignPrimaryTokenPrivilege" hinzu.
# Erfordert Administratorrechte und einen Neustart.

param(
    [string]$UserName = $env:USERNAME   # Standard: aktuell angemeldeter Benutzer
)

# Prüfe Administratorrechte
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Dieses Skript muss als Administrator ausgeführt werden!" -ForegroundColor Red
    exit 1
}

# Temporäre Dateien
$secPolFile = "$env:TEMP\secpol_export.inf"
$secPolModified = "$env:TEMP\secpol_modified.inf"
$logFile = "$env:TEMP\secedit_log.txt"

# 1. Aktuelle SID des Benutzers ermitteln
try {
    $user = Get-LocalUser -Name $UserName -ErrorAction Stop
    $sid = $user.Sid.Value
    Write-Host "[+] Benutzer '$UserName' hat SID: $sid" -ForegroundColor Green
} catch {
    Write-Host "[-] Benutzer '$UserName' nicht gefunden. Bitte existierenden Benutzernamen angeben." -ForegroundColor Red
    exit 1
}

# 2. Aktuelle Sicherheitsrichtlinie exportieren
Write-Host "[*] Exportiere aktuelle Sicherheitsrichtlinie nach $secPolFile ..."
secedit /export /cfg $secPolFile /areas USER_RIGHTS
if (-NOT (Test-Path $secPolFile)) {
    Write-Host "[-] Export fehlgeschlagen." -ForegroundColor Red
    exit 1
}

# 3. Die Zeile "SeAssignPrimaryTokenPrivilege" auslesen und erweitern
$content = Get-Content $secPolFile
$linePattern = "^SeAssignPrimaryTokenPrivilege\s*=\s*(.*)"
$found = $false
$newLine = ""

for ($i=0; $i -lt $content.Count; $i++) {
    if ($content[$i] -match $linePattern) {
        $existing = $matches[1].Trim()
        # Prüfen, ob die SID bereits enthalten ist
        if ($existing -match $sid) {
            Write-Host "[!] SID $sid ist bereits in SeAssignPrimaryTokenPrivilege enthalten. Nichts zu tun." -ForegroundColor Yellow
            $found = $true
            break
        }
        # Neue Zeile: bestehende Rechte + neue SID (mit Komma getrennt, kein Leerzeichen nach Komma)
        if ($existing -eq "") {
            $newEntry = "*$sid"
        } else {
            $newEntry = "$existing,*$sid"
        }
        $newLine = "SeAssignPrimaryTokenPrivilege = $newEntry"
        $content[$i] = $newLine
        $found = $true
        Write-Host "[+] Füge SID $sid hinzu." -ForegroundColor Green
        break
    }
}

if (-NOT $found) {
    # Falls die Zeile gar nicht existiert, neu anfügen
    Write-Host "[+] Zeile 'SeAssignPrimaryTokenPrivilege' nicht gefunden, wird neu angelegt." -ForegroundColor Green
    $content += "`nSeAssignPrimaryTokenPrivilege = *$sid"
}

# 4. Geänderte Datei speichern
$content | Out-File -FilePath $secPolModified -Encoding ascii
Write-Host "[*] Gespeichert: $secPolModified"

# 5. Neue Richtlinie importieren
Write-Host "[*] Importiere geänderte Richtlinie ..."
secedit /configure /db $env:TEMP\secedit.sdb /cfg $secPolModified /areas USER_RIGHTS /log $logFile

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Richtlinie erfolgreich aktualisiert." -ForegroundColor Green
    Write-Host "[!] Ein Neustart ist erforderlich, damit die Änderung wirksam wird!" -ForegroundColor Cyan
    $answer = Read-Host "Jetzt neu starten? (J/N)"
    if ($answer -eq 'J' -or $answer -eq 'j') {
        Restart-Computer -Force
    } else {
        Write-Host "Bitte starten Sie das System manuell neu, damit 'SeAssignPrimaryTokenPrivilege' aktiv wird."
    }
} else {
    Write-Host "[-] Import fehlgeschlagen. Siehe Log: $logFile" -ForegroundColor Red
}