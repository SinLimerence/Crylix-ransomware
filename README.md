# Ransomware (Educational Purposes Only)



## Overview
This repository contains a ransomware script designed to demonstrate:
- File encryption techniques
- System persistence mechanisms
- Anti-analysis methods
- Ransom note delivery systems

The code is provided for **cybersecurity education, penetration testing training, and defensive research**.

## Features
- **AES-256 Encryption** with chaotic key generation
- **Persistence Mechanisms**:
  - Disables Task Manager
  - Blocks common termination methods
  - Maintains window persistence
  - Registry Run Key (user login)
  - Scheduled Task (system-wide, hidden)
  - WMI Event Subscription (survives most cleanup attempts)
- **Anti-Analysis**:
  - Disables Windows Defender
  - Adds exclusion paths
  - Disables script scanning

## Visual

<img width="958" height="485" alt="Screenshot 2025-07-28 222718" src="https://github.com/user-attachments/assets/5278ed2a-a8ac-40e5-b612-cb24a5a514a4" />



<img width="466" height="300" alt="Screenshot 2025-07-28 204737" src="https://github.com/user-attachments/assets/8ebe3cee-8c05-4c78-ab51-151ec4437f61" />





## Compiling with Nuitka
```
1. pip install nuitka
2. pip install ordered-set zstandard
3. python -m nuitka --onefile --windows-disable-console --follow-imports Crylix.py
```


## Legal Disclaimer
❗ This software is provided **for legal educational purposes only**. The author:
- Does not condone illegal use
- Is not responsible for any misuse
- Recommends only using in controlled lab environments
Violating laws with this software may result in criminal prosecution.

## Installation
1. Install file.
2. Run setup.py.
3. Modify code how you want.
4. Run it or smth idk.
