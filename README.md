# frida_tools_GUI

A lightweight Windows GUI wrapper for common Frida workflows (Spawn/Attach + JS picker + package search + server launcher).  
Built for convenience when typing Frida commands repeatedly is annoying.

> Note: This project was generated with AI (GPT) out of boredom / for fun, mainly to streamline daily usage.

---

## Table of Contents
- [Features](#features)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Usage Flow](#usage-flow)
- [Common Issues](#common-issues)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features
- **ADB readiness check**
  - Ensures `adb` is available
  - Enforces **single-device** mode (avoids attaching to the wrong device)
- **Frida server launcher (device-side)**
  - Scans and starts `frida*` under:
    - `/data/local/tmp/hacktools`
  - Runs with `su -c` and sets executable permission
- **Package search & selection**
  - Search package names using a keyword (`pm list packages`)
  - Select from list or **manually input** a package name
- **Spawn / Attach**
  - **Spawn**: restart target app and inject script
  - **Attach**: attach to an existing process; if not running, optionally launches app via `monkey`
- **JS script picker**
  - Auto-detects `*.js` in the current directory
- **Real-time output**
  - Streams Frida output to GUI log panel
- **Cancel / Stop**
  - **Stop** (Ctrl+C / Ctrl+Break best-effort)
  - **Force kill** (terminate process immediately)

---

## Screenshots
> Add your screenshots under `./screenshots/` and update links below.

- Main window: `screenshots/main.png`
- Running example: `screenshots/running.png`

```text
Tip: On GitHub you can upload images by dragging them into an Issue/README editor,
then copy the generated URL or commit the images into /screenshots.
