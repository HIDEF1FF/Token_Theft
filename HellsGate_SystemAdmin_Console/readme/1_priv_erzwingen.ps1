# 1. Temporäre Pfade definieren
$tempDir = "C:\Windows\Temp"
$cfgFile = "$tempDir\sec_config.inf"
$dbFile  = "$tempDir\sec_local.sdb"

# 2. Die universelle SID der lokalen Administratoren-Gruppe holen (S-1-5-32-544)
$adminSID = (Get-LocalGroup -Name "Administratoren").SID.Value
if (-not $adminSID) {
    # Fallback, falls das OS auf Englisch läuft
    $adminSID = (Get-LocalGroup -Name "Administrators").SID.Value
}

Write-Host "Gefundene Administratoren-SID: $adminSID" -ForegroundColor Cyan

# 3. Aktuelle Sicherheitsrichtlinien exportieren
Write-Host "Exportiere aktuelle Sicherheitsrichtlinien..." -ForegroundColor Yellow
secedit /export /cfg $cfgFile /areas USER_RIGHTS | Out-Null

# 4. Prüfen, ob der Eintrag bereits existiert und Datei manipulieren
if (Test-Path $cfgFile) {
    $content = Get-Content $cfgFile -Encoding Unicode
    $found = $false
    $updatedContent = foreach ($line in $content) {
        if ($line -match "^SeAssignPrimaryTokenPrivilege\s*=") {
            $found = $true
            # Wenn die SID noch nicht in der Zeile steht, fügen wir sie hinzu
            if ($line -notlike "*$adminSID*") {
                # Entferne eventuelle Leerzeichen am Ende und hänge die neue SID an
                $line.Trim() + ",*$adminSID"
            } else {
                $line
            }
        } else {
            $line
        }
    }

    # Falls das Recht noch gar nicht in der Datei existiert, fügen wir es unter [Privilege Rights] ein
    if (-not $found) {
        $updatedContent = foreach ($line in $content) {
            $line
            if ($line -match "\[Privilege Rights\]") {
                "SeAssignPrimaryTokenPrivilege = *$adminSID"
            }
        }
    }

    # Geänderte Konfiguration speichern
    $updatedContent | Out-File $cfgFile -Encoding Unicode

    # 5. Geänderte Richtlinien auf dem System erzwingen (Import)
    Write-Host "Wende neue Rechte-Zuweisung auf das System an..." -ForegroundColor Yellow
    secedit /configure /db $dbFile /cfg $cfgFile /areas USER_RIGHTS | Out-Null

    # 6. Aufräumen
    Remove-Item $cfgFile -ErrorAction SilentlyContinue
    Remove-Item $dbFile -ErrorAction SilentlyContinue

    Write-Host "Erfolgreich! Die Berechtigung 'SeAssignPrimaryTokenPrivilege' wurde erzwungen." -ForegroundColor Green
    Write-Host "HINWEIS: Starten Sie den PC neu, damit die Änderungen für Ihr Konto aktiv werden." -ForegroundColor Magenta
} else {
    Write-Error "Fehler beim Exportieren der Sicherheitsrichtlinien."
}
