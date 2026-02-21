Audit Reporter GUI (Qt6 + C++17) — Import Reports (no active scanning)

This app does NOT perform active port scanning or active injection testing.
It imports authorized scan reports and produces a consolidated report.json.

Supported inputs:
- Ports:
  - ports.txt (protocol,port,state,service) OR
  - Nmap XML (.xml)
- Web alerts:
  - alerts.txt (TAB-separated) OR
  - OWASP ZAP JSON (.json)

Build (Windows / VS 2026):
  Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
  cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
    -DQt6_DIR="C:\Qt\6.10.1\msvc2022_64\lib\cmake\Qt6" `
    -DCMAKE_GENERATOR_INSTANCE="C:\Program Files\Microsoft Visual Studio\18\Community"
  cmake --build build --config Release

Run:
  .\build\Release\audit_reporter_gui.exe

Deploy Qt DLLs:
  New-Item -ItemType Directory -Force .\deploy | Out-Null
  Copy-Item .\build\Release\audit_reporter_gui.exe .\deploy\
  & "C:\Qt\6.10.1\msvc2022_64\bin\windeployqt.exe" --release --no-translations .\deploy\audit_reporter_gui.exe

Note:
- Keep your project path ASCII-only to avoid toolchain issues.
