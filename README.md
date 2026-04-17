Silent Infiltration
Time Shifted Elevation: Vom Multi Mechanismus Framework zum graphbasierten Perfect Disguise – Eine Blue  & Red Team Analyse“

Diese 4 Quelltexte sind Quelltexte zum Buch :

Geschrieben von Mr.HIDE 

Notwendige NuGet Pakete für pe1.cs
xml

xml
<PackageReference Include="TaskScheduler" Version="2.11.0" />
<PackageReference Include="System.Management" Version="8.0.0" />

csc.exe /reference:System.Management.dll /reference:Microsoft.Win32.TaskScheduler.dll pe1.cs

Notwendige NuGet Pakete für pe2.cs und pe3.cs:
xml

<PackageReference Include="TaskScheduler" Version="2.11.0" />

Kompilierung:

bash

csc.exe /reference:Microsoft.Win32.TaskScheduler.dll pe2.cs
bzw.:
csc.exe /reference:Microsoft.Win32.TaskScheduler.dll pe3.cs




