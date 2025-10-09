# 🧠 Challenge: Registry Persistence Hunt

## 🔍 Overview

A compromised workstation was discovered within our corporate network. The cybersecurity team obtained a copy of the system’s **Windows registry hive**. Your task is to analyze it and uncover any **persistence mechanisms** used by the attacker to maintain access.

---

## 🎯 Objective

Identify the persistence mechanism(s) in the registry and **submit the flag** in the challenge portal.

---

## 🔑 What to Look For

Persistence entries are often located in these registry keys:

* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

Look for:

* Suspicious or obfuscated executable paths
* Base64 or encoded command lines
* Services with abnormal `ImagePath` values
* DLL injection points or startup scripts

---

## 🧰 Suggested Tools

You can analyze registry hives using these tools:

* **RegRipper** (`rip.pl`, `rip.exe`, or GUI version)
* **RegRipper Plugins** — e.g., `run.pl`, `autoruns.pl`
* **python-registry** (Python library)
* **regripper2** / **regrippy**
* **strings**, `grep`, or manual inspection for quick searches

Example command:

```bash
rip.pl -r NTUSER.DAT -p run
```

---

## 💡 Hints

* Start with the `Run` keys under `HKCU` and `HKLM`.
* Check `Services` for unexpected startup binaries.
* Look at timestamps to spot recently modified entries.
* The **flag** may appear as part of a key name, value, or comment.

---


## 🏆 Challenge Details

* **Points:** 725
* **Difficulty:** Medium

---
