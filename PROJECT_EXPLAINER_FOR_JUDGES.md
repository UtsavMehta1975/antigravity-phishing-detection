# 🛡️ AntiGravity: Phishing & Malicious URL Provenance Engine
### Project Summary & Pitch Guide for Judges (Non-Technical & Executive Overview)

---

## 💡 1. The Real-World Problem We Solve

Most people think phishing is just a badly spelled email asking for a gift card. **Today, that is no longer true.** 

Modern cyber attackers have evolved beyond basic email filters:
1. **They hide malicious files inside innocent pictures:** Attackers attach `.svg` graphics or `.html` documents that assemble malware directly inside your computer's memory (**HTML & SVG Smuggling**). Standard email filters think it's just a harmless picture.
2. **They use QR Codes ("Quishing"):** Attackers send an image of a QR code knowing email filters can't read links inside pictures. An employee scans it with their phone, bypassing all company firewalls.
3. **They use Lookalike Letters ("Homoglyphs"):** Attackers use Cyrillic or Greek letters that look identical to human eyes (e.g., swapping Latin `a` with Russian `а`) or insert invisible spaces between characters so keyword filters get confused.
4. **They hide behind CAPTCHA walls:** When a security bot tries to inspect the link, the attacker shows a Cloudflare or CAPTCHA screen. Traditional tools get blocked and assume the website is clean.

Traditional antivirus checks static "blocklists." **If an attacker created a new link 10 minutes ago, traditional tools fail.**

---

## 🚀 2. What AntiGravity Does (In Simple Words)

Think of **AntiGravity** as a **Digital Forensic Detective**. 

Instead of just checking if a link is on a "known bad list", AntiGravity conducts a complete multi-step investigation:
- It opens the digital envelope.
- It scans images for hidden QR codes using computer vision.
- It unpacks attachments to see if hidden download triggers are lurking inside.
- It traces every redirect step-by-step.
- It draws a visual **"Evidence Crime Map"** that connects the sender to the final stolen password page.

---

## 🔍 3. The 5 Core Superpowers of the System

### 🦸 1. The X-Ray Scanner (Neutralizing File Smuggling)
- **The Trick:** Attackers send what looks like an invoice image. When opened, hidden code silently pieces together a virus in the background.
- **Our Defense:** AntiGravity inspects the raw code of SVG and HTML attachments. It instantly spots and neutralizes automated download triggers and hidden file assembly routines before they ever touch the computer.

### 🦸 2. The QR Code Hunter ("Quishing" Defense)
- **The Trick:** Attackers email a document saying: *"Scan this QR code with your phone to verify your payroll."*
- **Our Defense:** Our system has a built-in computer vision camera scanner. It automatically finds any QR code in attached images or PDFs, sharpens the contrast, decodes the target web address, and tests it.

### 🦸 3. The Disguise Unmasker (Character & Typosquatting Stripping)
- **The Trick:** Attackers insert invisible zero-width spaces or use alphabet lookalikes to fool search filters (like `p a y p a l` with invisible gaps).
- **Our Defense:** We peel away all invisible characters, normalize foreign alphabets back to standard English, and use mathematical fuzzy matching to catch impostors (e.g., catching `idshopee-59.blogspot.com` pretending to be the popular e-commerce app *Shopee*).

### 🦸 4. The Interactive "Evidence Crime Map" (Directed Graph)
- **The Trick:** Attackers bounce a victim through 3 or 4 different websites before reaching the fake login page.
- **Our Defense:** Our system connects the dots into a live, interactive map:
  $$\text{Email Sender} \longrightarrow \text{Suspicious Attachment} \longrightarrow \text{QR Code / Link} \longrightarrow \text{Redirect Hops} \longrightarrow \text{Fake Login Page} \longrightarrow \text{Stolen Password}$$
  It highlights the **Critical Risk Path** with a glowing red trail so anyone can instantly understand how the attack works.

### 🦸 5. Honest AI: Handling the "Unknown" State
- **The Trick:** Attackers put a "Verify you are human" CAPTCHA screen on their phishing website to stop security scanners from seeing the fake login form.
- **Our Defense:** Many older security tools mistakenly say: *"We didn't see any virus, so this website must be safe!"* AntiGravity is smarter: it detects the evasion wall, explicitly flags the destination as **UNKNOWN / GUARDED**, and warns the user never to enter details.

---

## 👥 4. The Dual-Layer Interface: Built for Two Audiences

Security tools usually fail because they are either **too complicated for regular staff** or **too basic for IT professionals**. AntiGravity solves this with a **Dual-Layer Interface**:

### 1️⃣ For Everyday Employees: The "Recipient View"
- **No confusing technical jargon.**
- Big, clear security badges: **SAFE (Green)**, **CAUTION (Yellow)**, or **CRITICAL PHISHING (Red)**.
- Explains the risk in plain human English:
  > *"This email claims to be Microsoft Support, but the link actually leads to an unregistered website created 2 days ago. Do not enter your password."*
- Single-click action buttons: **"Report to Security"** and **"Quarantine & Block Sender"**.

### 2️⃣ For IT & Security Analysts: The "Analyst View"
- The complete interactive **Evidence Graph** (you can click and drag nodes).
- Deep inspection of email headers (cryptographic SPF, DKIM, DMARC validation).
- Live threat intelligence matches (OpenPhish, PhishTank, URLhaus, ICANN domain registration age).
- **NIST-Compliant Explainable AI (XAI)** breakdown explaining the exact mathematical confidence score and reasoning.
- **Feedback & Allow-Override Log**: If a legitimate email was mistakenly flagged, an IT analyst can override it with auditable notes stored in the database.

---

## 📊 5. Proven Results on Real Attacks

We tested the platform against **32 diverse, live malicious links** including banking credential harvesters, free-hosting abuse sites, and direct malware drops:
- **Detection Rate:** **100% (32 out of 32 malicious links caught)**
- **Average Analysis Time:** **Less than 0.6 seconds** per item
- **Safety First:** Outbound downloads are safely sandboxed and bypassed so testing never risks infecting the user's computer.

---

## ⚡ 6. Quick 30-Second Demonstration Script for Judges

1. **Open the Dashboard:** Navigate to `http://localhost:1511` (or the deployed Render web address).
2. **Show Recipient View:** 
   - Click the **"⚡ SVG Smuggling Attack (.eml)"** one-click button.
   - Show how clear and easy the warning card is for a non-technical employee.
3. **Switch to Analyst View:**
   - Click the **"Analyst View"** button in the top right.
   - Point out the **Evidence Graph Canvas**: show the glowing red trail connecting the email to the hidden executable payload.
   - Click on any bubble in the graph to show the technical forensic details on the right panel.
4. **Show Cloudflare Evasion Defense:**
   - Click **"⚡ Cloudflare Evasion Wall (UNKNOWN)"**.
   - Explain: *"Notice how our engine doesn't blindly trust a website just because it has a CAPTCHA wall—it flags the evasion technique and marks it as UNKNOWN."*

---

## 🏆 7. Summary: Why This Matters

Phishing remains the **#1 cause of corporate data breaches worldwide**. Attackers have weaponized modern tricks like image smuggling and QR codes because legacy software can't see them.

**AntiGravity brings security back into the light** by combining computer vision, deep feature extraction, and explainable evidence maps into a platform that protects everyday employees while giving security teams the deep forensics they need.
