Silent Infiltration

Der Quelltext Program.cs ist der Quelltext zum Buch (ohne Kernel unhook implementation):
(pe.cs ist die Ausgangsquelltext wird nicht gebraucht, dient nur für Archivierung)

Öffne PowerShell als Administrator.

Dann disen Einzeiler ausführen:


$sid = (Get-LocalUser -Name $env:USERNAME).Sid.Value; $file = "$env:TEMP\secpol.inf"; secedit /export /cfg $file /areas USER_RIGHTS > $null; (Get-Content $file -Encoding Unicode) -replace '(SeAssignPrimaryTokenPrivilege\s*=\s*)(.*)', { $groups = $_.Groups; if ($groups[2].Value -notmatch [regex]::Escape($sid)) { "$($groups[1].Value)$($groups[2].Value),*$sid" } else { $_.Value } } | Set-Content $file -Encoding Unicode; if ((Get-Content $file | Select-String "SeAssignPrimaryTokenPrivilege").Matches.Count -eq 0) { Add-Content $file "`nSeAssignPrimaryTokenPrivilege = *$sid" }; secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $file /areas USER_RIGHTS /log "$env:TEMP\secedit.log"


Falls die datei bereinigen müssen:


# 1. Lösche alle temporären Dateien
Remove-Item "$env:TEMP\secpol.inf" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secedit.sdb" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\secedit.log" -Force -ErrorAction SilentlyContinue

# 2. Exportiere die Richtlinie neu (ohne Änderungen)
secedit /export /cfg "$env:TEMP\secpol.inf" /areas USER_RIGHTS

# 3. Prüfe, ob die Datei korrekt erstellt wurde
if (Test-Path "$env:TEMP\secpol.inf") {
    Write-Host "[+] Export erfolgreich" -ForegroundColor Green
    
    # 4. Lese die Datei als Text
    $content = Get-Content "$env:TEMP\secpol.inf" -Encoding Unicode
    
    # 5. Prüfe, ob die Zeile existiert
    $line = $content | Select-String "SeAssignPrimaryTokenPrivilege"
    
    if ($line) {
        Write-Host "[+] Zeile gefunden: $($line.Line)" -ForegroundColor Green
        # Entferne die Zeile temporär
        $content = $content | Where-Object { $_ -notmatch "SeAssignPrimaryTokenPrivilege" }
    }
    
    # 6. Neue Zeile mit aktueller SID erstellen
    $sid = (Get-LocalUser -Name $env:USERNAME).Sid.Value
    $newLine = "SeAssignPrimaryTokenPrivilege = *$sid"
    Write-Host "[+] Neue Zeile: $newLine" -ForegroundColor Green
    
    # 7. Neue Zeile hinzufügen
    $content += $newLine
    
    # 8. Datei im richtigen Format speichern (wichtig: Unicode mit BOM)
    $utf8WithBom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllLines("$env:TEMP\secpol_new.inf", $content, $utf8WithBom)
    
    # 9. Importieren
    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol_new.inf" /areas USER_RIGHTS /log "$env:TEMP\secedit.log"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Richtlinie erfolgreich aktualisiert!" -ForegroundColor Green
        Write-Host "[!] Neustart erforderlich!" -ForegroundColor Yellow
    } else {
        Write-Host "[-] Fehler beim Import. Zeige Log:" -ForegroundColor Red
        Get-Content "$env:TEMP\secedit.log" -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "[-] Export fehlgeschlagen" -ForegroundColor Red
}


