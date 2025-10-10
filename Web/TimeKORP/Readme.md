# TimeKORP — Super Beginner-Friendly Writeup

**Challenge name**: TimeKORP  
**Points**: 300

## 🧠 What this challenge is about
A basic web app shows the current time based on a "format" you pick. Your goal: Hack it to run your own commands and steal the secret `/flag` file.  
- **Use Command Injection**—sneak bad input into the format to trick the server into running extra code.  
- **Why do this?** It's a top web bug (OWASP Top 10) that can crash servers.

## Setup
- Launch TimeKORP on HTB—get URL like `http://YOUR_IP:PORT`.  
- Download files: `TimeController.php`, `TimeModel.php`.  

**Why?** Lab = safe playground. Code = your cheat sheet to the bug.

## Steps: What to Do and Why

### 1. Check the Page
- **Do**: Type the URL into your browser. You see time like `14:30:45` from `?format=%H:%M:%S`. Right-click the page > "Inspect" (or `Ctrl+Shift+I`) to see source: It's just jQuery stuff (ignore it).  
- **Why?** This spots the `format` param—it's user input you can change, like tweaking a video game's settings. Start here to see what's controllable.

### 2. Peek at TimeController.php
- **Do**: Open `TimeController.php` in a text editor (like Notepad or VS Code). Look for `$_GET['format']`—it grabs your URL input and passes it raw (no cleaning). Test now: Change URL to `?format=%H:%S:%M` and reload—time swaps order (e.g., `14:45:30`)?  
- **Why?** Raw inputs are a hack alert. It shows the app trusts your changes too much, opening the door for tricks. This quick test proves input goes straight through.

### 3. Check TimeModel.php
- **Do**: Open `TimeModel.php`. Look at `__construct`: It runs `shell_exec('date \'' . $format . '\' 2>&1')`. This makes a command like `date '%H:%M:%S' 2>&1` with your input inside quotes.  
- **Why?** `shell_exec` runs real computer commands. You can break the quotes (`'`) to add your own, like sneaking extra instructions into a recipe. This is the "boom" spot where your hack happens.

### 4. Test the Hack
- **Do**: In the URL, add this payload: `'; ls` (lists files; replace spaces with `%20` so it works in URL). Full example: `http://YOUR_IP:PORT?format=';%20ls%20`. Reload—page shows files like `index.php`?  
- **Why?** This safe test proves you control it (`;` ends the time command, `'` closes/reopens quotes). It's like checking if your key fits the lock before turning it—builds confidence without risk.

### 5. Steal the Flag
- **Do**: From the file list, spot `../flag` (parent folder). Swap payload to `'; cat ../flag` (reads file). Full URL: `http://YOUR_IP:PORT?format=';%20cat%20../flag%20`. Reload—flag appears (like `HTB{time_to_inject}`)! Copy and submit to HTB.  
- **Why?** `cat` reads files, `../` goes up one folder. Now you've fully hacked it—like opening the treasure chest. This wins the challenge.<img width="1803" height="634" alt="image" src="https://github.com/user-attachments/assets/68e5248a-bbcd-4fb5-811a-56d36549d8e4" />


## The Bug: Command Injection
- **What?** Dirty input runs your code via shell (e.g., read files).  
- **Why happens?** PHP glues strings without checks—use `escapeshellarg()` to fix.
