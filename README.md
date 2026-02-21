# Audit Reporter (Qt6 / C++17) 

## What it is
**Audit Reporter** is a desktop application (Qt6 Widgets) that **imports** results from *authorized* audit reports (open ports and web findings) and produces a single consolidated **`report.json`** file. A lightweight **CLI** is also included.

**Important:** This application **does not perform active port scanning** and **does not probe/exploit** (e.g., SQLi/XSS). It is a *report aggregator / reporting tool*.

## Purpose
- Consolidate multiple tool outputs into a common JSON schema.
- Quickly review and filter results (protocol, severity/risk).
- Generate a clean report for archiving, QA, or delivery to clients/teams.

## Supported inputs
1) **Ports**
- `ports.txt` (CSV per line): `protocol,port,state,service`
- **Nmap XML**: `.xml` containing `<port protocol="..." portid="..."><state state="open"/>...`

2) **Web alerts**
- `alerts.txt` (TSV per line):  
  `site<TAB>alert<TAB>risk<TAB>description<TAB>solution<TAB>reference`
- **OWASP ZAP JSON**: `.json` (typical structure `site[]` → `alerts[]`)

Sample files are provided under `inputs/` (`example_nmap.xml`, `example_zap.json`).

## Output
- `report.json` with:
  - `generated_at_utc`
  - `open_ports[]`
  - `web_alerts[]`

## Configuration (audit.ini)
The app can load/save settings from `audit.ini`:

- `[inputs]`  
  `ports_path` (txt or xml)  
  `alerts_path` (txt or json)

- `[filters]`  
  `min_risk` = `none|low|medium|high`  
  `only_protocol` = `tcp|udp|any`

- `[output]`  
  `report_json` = output path for the consolidated JSON

## GUI usage
1) Launch `audit_reporter_gui`.
2) Select the inputs (Ports & Alerts).
3) Set filters (Protocol, Min risk).
4) Click **Run** → writes `report.json` and previews it in the lower panel.

## CLI usage
```bash
audit_reporter_cli audit.ini
```

## Build on Windows (Visual Studio + CMake)
Prerequisites:
- Visual Studio (C++ workload)
- CMake
- Qt 6 (MSVC x64 build)

Example (PowerShell):
```powershell
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue

cmake -S . -B build -G "Visual Studio 18 2026" -A x64 `
  -DQt6_DIR="C:\path\to\qt\msvc2022_64\lib\cmake\Qt6" `
  -DCMAKE_GENERATOR_INSTANCE="C:\Program Files\Microsoft Visual Studio\18\Community"

cmake --build build --config Release
```

Run:
```powershell
.\build\Release\audit_reporter_gui.exe
```

### Deploy Qt DLLs next to the exe
To run on a machine without a Qt installation, deploy with `windeployqt`:
```powershell
New-Item -ItemType Directory -Force .\deploy | Out-Null
Copy-Item .\build\Release\audit_reporter_gui.exe .\deploy\

& "C:\path\to\qt\msvc2022_64\bin\windeployqt.exe" `
  --release --no-translations `
  .\deploy\audit_reporter_gui.exe
```

## Build on Linux (Qt6 + CMake)
Prerequisites:
- CMake
- C++ compiler (g++/clang)
- Qt6 development packages

Example (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install -y build-essential cmake qt6-base-dev
```

Build:
```bash
rm -rf build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Run:
```bash
./build/audit_reporter_gui
```


