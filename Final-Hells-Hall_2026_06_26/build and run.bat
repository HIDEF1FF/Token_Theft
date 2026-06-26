@echo off
echo ========================================
echo  HELLSHALL EMBEDDED INJECTOR
echo  PAYLOAD ALS RESOURCE - NUR IM RAM!
echo ========================================
echo.

cd /d "C:\Users\RMW PC 2 ueb\Desktop\HellsHall\Loader"

:: 1. Payload DLL bauen
echo [1/3] Building Payload DLL...
cd ..\Loader
dotnet build ..\HellsHallPayload.csproj -c Release -o ..\bin\Release
if errorlevel 1 (
    echo [!] Payload build failed!
    pause
    exit /b 1
)
cd ..\Loader

:: 2. Prüfen ob Payload DLL existiert
echo [2/3] Checking payload DLL...
if not exist "..\bin\Release\HellsHallPayload.dll" (
    echo [!] Payload DLL not found!
    pause
    exit /b 1
)
echo [+] Payload found: ..\bin\Release\HellsHallPayload.dll

:: 3. ReflectiveInjector bauen (mit Resource)
echo [3/3] Building ReflectiveInjector with embedded resource...

:: Projektdatei mit Resource erstellen
(
echo ^<Project Sdk="Microsoft.NET.Sdk"^>
echo   ^<PropertyGroup^>
echo     ^<TargetFramework^>net48^</TargetFramework^>
echo     ^<OutputType^>Exe^</OutputType^>
echo     ^<PlatformTarget^>x64^</PlatformTarget^>
echo     ^<AllowUnsafeBlocks^>true^</AllowUnsafeBlocks^>
echo     ^<LangVersion^>latest^</LangVersion^>
echo     ^<GenerateAssemblyInfo^>false^</GenerateAssemblyInfo^>
echo     ^<GenerateTargetFrameworkAttribute^>false^</GenerateTargetFrameworkAttribute^>
echo     ^<AssemblyName^>ReflectiveInjector^</AssemblyName^>
echo     ^<RootNamespace^>HellsHallInjector^</RootNamespace^>
echo     ^<Deterministic^>false^</Deterministic^>
echo     ^<NoWarn^>CS0579;CS1701;CS1702^</NoWarn^>
echo     ^<Nullable^>disable^</Nullable^>
echo   ^</PropertyGroup^>
echo   ^<ItemGroup^>
echo     ^<EmbeddedResource Include="..\bin\Release\HellsHallPayload.dll"^>
echo       ^<LogicalName^>HellsHallInjector.HellsHallPayload.dll^</LogicalName^>
echo     ^</EmbeddedResource^>
echo   ^</ItemGroup^>
echo   ^<ItemGroup^>
echo     ^<Reference Include="System" /^>
echo     ^<Reference Include="System.Core" /^>
echo     ^<Reference Include="System.Management" /^>
echo     ^<Reference Include="Microsoft.CSharp" /^>
echo   ^</ItemGroup^>
echo ^</Project^>
) > ReflectiveInjector.csproj

:: Build mit dotnet
dotnet build ReflectiveInjector.csproj -c Release -o ..\bin\Release

if errorlevel 1 (
    echo [!] ReflectiveInjector build failed!
    pause
    exit /b 1
)

echo.
echo ========================================
echo  BUILD COMPLETE!
echo ========================================
echo.
echo [+] ReflectiveInjector.exe erstellt
echo [+] Payload embedded as RESOURCE
echo [+] Payload NUR IM RAM - KEINE FESTPLATTE!
echo.
echo To run: ..\bin\Release\ReflectiveInjector.exe --console
pause