# Hack The Box: Shush Protocol - PLC Flag Extraction Guide

## Overview
This guide will walk you, step-by-step, through extracting the PLC flag in the "Shush Protocol" Hack The Box challenge using Wireshark. It’s written for beginners, with every command inside the file and nothing segregated.

---

## Prerequisites
- Wireshark installed on your system
- The challenge `.pcap` file from Hack The Box

---

## Step-by-Step Instructions

### 1. Open the Capture File
- Start Wireshark.
- Click **File → Open** (or press Ctrl+O).
- Select your `.pcap` file.

### 2. Identify the Device IPs
- Go to **Statistics > Endpoints > IPv4** in Wireshark.
- Note the IPs for the PLC (e.g., `192.168.178.23`) and the client PC (`192.168.178.105`).

### 3. Filter by IP Addresses
- In Wireshark’s display filter bar, enter:ip.addr == 192.168.178.23 && ip.addr == 192.168.178.105
- Press Enter.
- This focuses your view to just traffic between those two devices.

### 4. Filter by Modbus/TCP Port
- Narrow it further by adding the port filter:ip.addr == 192.168.178.23 && ip.addr == 192.168.178.105 && tcp.port == 502
- - Press Enter.
- Most PLC traffic uses Modbus protocol on port 502.

### 5. Find Custom Function Packets
- Look in the **Info** column for packets labeled:Func: 102: Unknown function (102)
- These custom packets likely carry the flag.

### 6. Follow the TCP Stream
- Right-click on any packet matching the above.
- Choose **Follow > TCP Stream**.
- In the window that opens, set "Show data as" to **ASCII**.
- This puts all conversation data in readable text.
- <img width="825" height="740" alt="image" src="https://github.com/user-attachments/assets/921495eb-560c-4507-8d41-56b9e09dcf5e" />


### 7. Find the Flag
- Hack The Box flags are always in the `HTB{...}` format.

### 8. Copy and Submit
- Copy the entire flag including braces.
- Paste it into the Hack The Box portal to complete the challenge.

---

## Tips & Troubleshooting

- If you don’t see Modbus traffic, try removing the port filter and browsing.
- Flags usually appear as readable ASCII text, not binary.
- Try following streams for other packet types if you don’t find the flag right away.
- Sometimes the flag will be in the reply packet, not the request.

---

## Key Wireshark Features Used

- **Display Filters:** Focus on relevant communications.
- **Endpoint Statistics:** Identify active devices on the network.
- **Follow TCP Stream:** Reassemble complete conversations.
- **ASCII View:** Easily spot human-readable flags.

---

