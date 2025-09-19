# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Mc-Cloud-Code-Cyber/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-for-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of successful outgoing connections using Tor.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labusermccloud" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-09-17T09:46:35.2615571Z`. These events began at `2025-09-17T09:35:29.0203877Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "javon-windows-l"
| where FileName startswith "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1535" height="455" alt="Screenshot 2025-09-19 031130" src="https://github.com/user-attachments/assets/6af6f462-ce76-4a1a-88e3-9947ac90f232" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.7.exe". Based on the logs returned, at `2025-09-17T09:37:36.1019349Z`, an employee "labusermccloud" on the "javon-windows-l" device ran the file `tor-browser-windows-x86_64-portable-14.5.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName contains "javon-windows-l"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1534" height="216" alt="Screenshot 2025-09-19 031518" src="https://github.com/user-attachments/assets/50db7d92-6b68-4881-941e-3022773a3717" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labusermccloud" actually opened the TOR browser. There was evidence that they did open it at `2025-09-17T09:38:19.9270396Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "javon-windows-l"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1534" height="475" alt="Screenshot 2025-09-19 031748" src="https://github.com/user-attachments/assets/b8aa6376-4ce7-429e-b8ec-58ed17d95c68" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-09-17T09:38:20.927366Z`, an employee on the "javon-windows-l" device successfully established a connection to the remote IP address `127.0.0.1` on port `51458`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labusermccloud\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `80,443 and 51000`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "javon-windows-l"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName == "tor.exe"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc 
```
<img width="1517" height="429" alt="Screenshot 2025-09-19 033546" src="https://github.com/user-attachments/assets/b4bfab5c-f357-41ca-b1f0-7baaec81053e" />

---

# Chronological Event Timeline 

## 📌 Timeline of Events (Tor-related only)

### **Initial Download & Execution**
- **2025-09-17 04:35:29** – File `tor-browser-windows-x86_64-portable-14.5.7.exe` appears in Downloads (renamed/copied event).  
- **2025-09-17 04:37:36** – User `labusermccloud` executes `tor-browser-windows-x86_64-portable-14.5.7.exe` (silent install initiated).

### **Installation Artifacts**
- **2025-09-17 04:37:50+** – Multiple Tor-related files are created on the Desktop under `Tor Browser\Browser\...` (e.g., `tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`).  
- **2025-09-17 04:46:35** – A file named `tor_shopping_list.txt` is created on Desktop.  

### **Tor Browser Usage**
- **2025-09-17 04:38:19** – Evidence of Tor Browser execution (`tor.exe`, `firefox.exe` processes).  
- **2025-09-19 02:22:15–02:22:20** – Multiple Tor-related processes spawn (`tor.exe`, `firefox.exe`).  

### **Network Activity**
- **2025-09-17 04:38:20** – `tor.exe` establishes a localhost connection (127.0.0.1:51458) — consistent with Tor client initialization.  
- **2025-09-19 02:22:21–02:22:56** – Outbound network traffic from `tor.exe` observed:  
  - Connections to **external IPs on port 443** (e.g., `185.220.101.104`, `64.65.62.111`) — typical Tor relay nodes.  
  - Localhost proxying activity also observed (`127.0.0.1` on ports 51797–51800).  

---

## 📝 Summary of Events
Between **Sept 17–19, 2025**, user **`labusermccloud`** on host **`javon-windows-l`** downloaded, installed, and actively used the **Tor Browser**.  

- The installation began at **04:35 AM Sept 17** with the execution of the installer.  
- By **04:38 AM**, the Tor client was launched and initiated local proxying.  
- Desktop artifacts (Tor-related files and a text file `tor_shopping_list.txt`) were created during setup.  
- On **Sept 19**, further process activity and outbound connections to Tor relay IPs confirm continued usage of the Tor Browser.  

**Overall:** The logs clearly show successful installation and use of the Tor Browser by the account `labusermccloud`, with both local proxy initialization and external relay connections established.

---

## Response Taken

TOR usage was confirmed on the endpoint `javon-windows-l` by the user `labusermccloud`. The device was isolated, and the user's direct manager was notified.

---
