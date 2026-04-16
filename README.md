Notwendige NuGet Pakete für pe2.cs und pe3.cs:
xml

<PackageReference Include="TaskScheduler" Version="2.11.0" />

Kompilierung:

bash

csc.exe /reference:Microsoft.Win32.TaskScheduler.dll pe2.cs
bzw.:
csc.exe /reference:Microsoft.Win32.TaskScheduler.dll pe3.cs

Diese 3 Quelltexte sind Quelltexte zum Buch :
Silent Infiltration
Time Shifted Elevation: Vom Multi Mechanismus Framework zum graphbasierten Perfect Disguise – Eine Blue  & Red Team Analyse“
Geschrieben von Mr.HIDE
