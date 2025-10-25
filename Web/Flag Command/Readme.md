# Dimensional Escape Quest – Flag Command

## Challenge Description

Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!

---

## Methodology

### 1. Reconnaissance & Setup

- Configured my browser to use **Burp Suite** as an HTTP/HTTPS proxy.
- Installed Burp's CA certificate to intercept encrypted web traffic.
- Explored every interactive feature of the application while monitoring requests in Burp's Proxy > HTTP history.

### 2. Endpoint Discovery

- Noticed that most requests were predictable, but started flexing for hidden API endpoints by watching XHR/Fetch requests and by searching code.
- Identified a suspicious endpoint: **`/api/monitor`**.
<img width="1527" height="853" alt="image" src="https://github.com/user-attachments/assets/362d964a-e8c1-462e-b34e-c3ff6c7ae4f7" />

### 3. Parameter Enumeration

- Observed that normal site navigation did not use this endpoint directly.
- Inspected JavaScript and noticed possible references to a `command` parameter.
- Examined error messages to infer required payload structure.

### 4. Request Crafting & Testing

- Used **Burp Suite's Repeater** to construct and test requests.
- Established that a **POST** request to `/api/monitor` with the header `Content-Type: application/json` was required.
- On missing or incorrect headers, received HTTP 415 (Unsupported Media Type) errors and adjusted accordingly.


### 5. Solving & Flag Retrieval

- Sent the following POST request:
    ```
    POST /api/monitor HTTP/1.1
    Host: <target-host>
    Content-Type: application/json

    {"command":"Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}
    ```
- Server response:
    ```
    {
      "message": "HTB{D3v3l0p3r_t00ls_4r3_b3st_wh4t_y0u_Th1nk??}"
    }
    ```
<img width="1238" height="314" alt="image" src="https://github.com/user-attachments/assets/83633f65-2c30-4a54-b12d-2dd8e33d0f26" />

---

## Tools Used

- **Burp Suite** - Proxy & HTTP request crafting
- **Browser DevTools** - JavaScript/XHR inspection
- **Manual API fuzzing & analysis**

---

## Reflections & Lessons

- Carefully inspecting app traffic is key to finding hidden or undocumented APIs.
- Properly setting headers (especially `Content-Type: application/json`) is essential for API interaction.
- Error messages often give critical clues about required payload structure.
- Success required a blend of technical analysis, creative troubleshooting, and CTF perseverance.

---

**This README details each step in solving the "Dimensional Escape Quest – Flag Command" through traffic interception, payload analysis, and targeted API interaction.**
