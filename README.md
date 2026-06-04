Silent Infiltration

Der Quelltext Program.cs ist der Quelltext zum Buch (ohne Kernel unhook implementation):
(pe.cs ist die Ausgangsquelltext wird nicht gebraucht, dient nur für Archivierung)

Öffne PowerShell als Administrator.

Dann disen Einzeiler ausführen:


PS C:\WINDOWS\system32> $sid = (Get-LocalUser -Name $env:USERNAME).Sid.Value; $file = "$env:TEMP\secpol.inf"; secedit /export /cfg $file /areas USER_RIGHTS > $null; (Get-Content $file -Encoding Unicode) -replace '(SeAssignPrimaryTokenPrivilege\s*=\s*)(.*)', { $groups = $_.Groups; if ($groups[2].Value -notmatch [regex]::Escape($sid)) { "$($groups[1].Value)$($groups[2].Value),*$sid" } else { $_.Value } } | Set-Content $file -Encoding Unicode; if ((Get-Content $file | Select-String "SeAssignPrimaryTokenPrivilege").Matches.Count -eq 0) { Add-Content $file "`nSeAssignPrimaryTokenPrivilege = *$sid" }; secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $file /areas USER_RIGHTS /log "$env:TEMP\secedit.log"
                                                                           n



