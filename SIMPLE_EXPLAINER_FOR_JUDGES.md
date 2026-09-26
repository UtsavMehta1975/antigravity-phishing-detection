# 🕵️ ShieldCheck: Explained So a 12-Year-Old Can Understand
### The 3 Big Questions: **WHAT**, **WHY**, and **HOW** (The Underlying Logic)

---

## 🎤 The 30-Second Elevator Pitch (Read This Aloud to Judges!)

> *"We built **ShieldCheck**—a smart cyber detective that catches modern hacker emails and fake links that fool traditional antivirus.* 
> 
> *Traditional tools only check if a link is on an old 'bad list'. But today, hackers hide viruses inside picture files, sneak fake links into QR codes, and use Russian lookalike letters. 
> 
> *Our engine acts like an airport X-ray machine: it unpacks hidden code, scans QR codes using computer vision, unmasks fake letters, and connects every step of the attack into an interactive 'crime map' so regular people stay safe and security experts know exactly what happened."*

---

## ❓ Question 1: WHAT Did We Make?

Imagine you have a private security guard standing next to your inbox:
1. **For Everyday People (Recipient View):** It shows a clean, simple traffic-light card:
   - 🟢 **GREEN**: Safe to open.
   - 🟡 **YELLOW**: Caution! Something looks fishy.
   - 🔴 **RED**: Dangerous attack! Do not click.
   - It explains the danger in simple English (e.g., *"This email claims to be Netflix, but the button actually sends you to an unregistered hacker website"*).
2. **For Cyber Experts (Analyst View):** It shows a live **"Detective Crime Board"** (Evidence Graph) that uses visual bubbles and red string to map out every hop the hacker took to try and trick you.

---

## ❓ Question 2: WHY Did We Make It?

Because **old antivirus software is stuck in the past**, while hackers have completely changed how they attack:

### 1. The "Harmless Picture" Trick (SVG Smuggling)
- **The Problem:** Old email filters only look for `.exe` files. So hackers hide dangerous code inside innocent vector image files (`.svg`). When you open the picture, hidden code glues a virus together in your computer's memory.
- **Why we built it:** To inspect the inside code of images before they can assemble malware.

### 2. The "Scan My Phone" Trick (Quishing)
- **The Problem:** Old filters read words, not pictures. So hackers take a screenshot of a QR code that says: *"Scan with your phone to verify your account."* Your work computer never sees the link, but your phone gets hacked.
- **Why we built it:** To give the computer "eyes" that read QR codes automatically.

### 3. The "Twin Letters" Trick (Homoglyphs)
- **The Problem:** In Russian (Cyrillic), the letter `а` looks 100% identical to the English letter `a`, but computers see them as different characters. Hackers register fake domains like `pаypal.com` to trick people.
- **Why we built it:** To strip out fake twin letters and reveal the true address.

### 4. The "10-Minute Website" Problem
- **The Problem:** Traditional antivirus uses a "blocklist" of known bad websites. But hackers create a new website, steal 100 passwords in 20 minutes, and throw it away. Old tools don't have it on their list yet.
- **Why we built it:** ShieldCheck doesn't just check a list; it investigates the **behavior, grammar, code, and hidden plumbing** of the link in real time.

---

## 🧠 Question 3: HOW Did We Make It? (The Step-by-Step Logic)

Here is the exact step-by-step recipe of what happens inside ShieldCheck's brain the millisecond an email or URL is entered:

```
[ Incoming Email or Link ]
           │
           ▼
  STEP 1: The Disguise Peeler (Unicode & Invisible Space Stripper)
           │
           ▼
  STEP 2: The X-Ray Machine (SVG/HTML Smuggling Code Inspector)
           │
           ▼
  STEP 3: The Robot Eyes (Computer Vision QR Code Decoder)
           │
           ▼
  STEP 4: The Lie Detector (Anchor Text vs Real Destination Mismatch)
           │
           ▼
  STEP 5: The Math Checker (Shannon Entropy & Randomness Scorer)
           │
           ▼
  STEP 6: The Detective Board (Directed Evidence Graph Builder)
           │
           ▼
  STEP 7: The Honest Verdict (NIST Explainable AI Output)
```

---

### 🔬 The 7 Logic Steps Explained Simply:

#### 🔹 Step 1: The Disguise Peeler (Normalization)
- **The Logic:** Hackers put invisible spaces (zero-width spaces) between letters or use foreign lookalike letters so security filters can't read words like `p-a-s-s-w-o-r-d`.
- **What ShieldCheck Does:** It scrubs the text, removes all invisible characters, translates Russian/Greek lookalikes into plain English, and unmasks the true words.

#### 🔹 Step 2: The X-Ray Machine (Attachment Smuggler Detection)
- **The Logic:** When someone sends an `.svg` or `.html` file, ShieldCheck reads the file's raw blueprint.
- **What ShieldCheck Does:** It looks for suspicious coding instructions like `new Blob()`, `URL.createObjectURL()`, or programmatic `.click()`. If it sees code trying to secretly assemble a downloadable file in memory, it sounds the alarm!

#### 🔹 Step 3: The Robot Eyes (Computer Vision Quishing Decoder)
- **The Logic:** If an email contains a picture or a PDF with an image, ShieldCheck uses computer vision (OpenCV).
- **What ShieldCheck Does:** It converts the image to high contrast black-and-white, finds the QR code pattern, decodes the secret web address hidden inside, and passes that link to the next step.

#### 🔹 Step 4: The Lie Detector (Mismatches & Spoofing)
- **The Logic:** In phishing emails, blue clickable text often says `https://login.microsoft.com`, but the actual hidden link behind it points to `http://hacker-login-box.top`.
- **What ShieldCheck Does:** It compares what the human sees vs where the link actually takes them. If they don't match, it flags a massive critical penalty score.

#### 🔹 Step 5: The Math Scorer (Shannon Entropy & Lure Keywords)
- **The Logic:** Humans make websites with normal words like `google.com`. Hackers use random robots to generate gibberish names like `x9q8w2z7k1v4m0p.xyz` or lure phrases like `software-update.exe`.
- **What ShieldCheck Does:** It calculates **Shannon Entropy** (a mathematical score of how chaotic or random the letters are). High randomness = likely a hacker computer program. It also checks for direct dangerous file downloads like `.exe` or `.ps1`.

#### 🔹 Step 6: The Crime Map (Directed Evidence Graph)
- **The Logic:** Instead of just outputting a single number, ShieldCheck connects all clues using a network graph:
  $$\text{Email Sender} \longrightarrow \text{Suspicious Image} \longrightarrow \text{Decoded Link} \longrightarrow \text{Redirect Hops} \longrightarrow \text{Fake Login Page}$$
- **What ShieldCheck Does:** It finds the **Critical Risk Path** (the most dangerous route through the clues) and lights it up in glowing red on an interactive canvas.

#### 🔹 Step 7: The Honest Verdict (Explainable AI)
- **The Logic:** If a hacker puts a Cloudflare or CAPTCHA screen in front of their site, older tools say *"We couldn't see any virus, so it's safe!"*
- **What ShieldCheck Does:** It is honest. It outputs **UNKNOWN / GUARDED**, warning the user: *"We cannot verify this site because it is hiding behind a verification wall."* It writes a clear paragraph explaining **WHY** it made its decision following official NIST Explainable AI standards.

---

## 📋 Quick Cheat Sheet for Judges

| Question | Short Answer |
| :--- | :--- |
| **What is it?** | A multi-modal cybersecurity platform that analyzes emails, links, QR codes, and image attachments to catch modern phishing attacks. |
| **Why is it special?** | It catches new attacks that traditional antivirus misses (like SVG smuggling, Quishing, and CAPTCHA evasion walls) instead of just relying on old blocklists. |
| **How fast is it?** | It runs in less than **0.6 seconds** per scan, running across all CPU cores. |
| **What was the result?** | **100% detection rate** on 32 live real-world attack links (malware downloads, credential harvesters, and typosquats). |
| **Who is it for?** | Both everyday employees (simplified risk cards) and security analysts (deep interactive evidence graph). |
