# Google Calendar Invite Abuse — Brand Impersonation Vishing Campaign

**Analyst:** Dan-Andrei Grigorescu
**Date analyzed:** June 2026
**Source:** Personal inbox (Yahoo Mail, Spam folder)
**Classification:** Vishing (Voice Phishing) Campaign — Low technical complexity, social-engineering driven

---

## Executive Summary

Between June 3–9, 2026, five near-identical emails were received in the same inbox, all abusing **Google Calendar's invitation system** to deliver fake billing/renewal notices impersonating well-known tech support brands (Geek Squad, McAfee, Norton). Unlike traditional phishing, none of the emails contained a malicious link — the attack relies entirely on **vishing**: convincing the recipient to call a phone number, where a live operator likely attempts to gain remote access or extract payment information.

Correlation across the five samples confirms this is a **single coordinated campaign**, not isolated spam, based on shared phone number fragments, identical email structure, and consistent infrastructure abuse patterns.

---

## Attack Vector: Why Calendar Invites?

Instead of sending a standard email, the attacker creates a Google Calendar event and adds the victim as an attendee. Google's infrastructure then auto-generates and sends the invitation on the attacker's behalf.

**Why this bypasses common defenses:**

| Standard Phishing Email | Calendar Invite Abuse |
|---|---|
| `From` domain often spoofed or freshly registered | `Sender:` header is literally `google.com` |
| DKIM frequently fails or is absent | DKIM **passes** for `google.com` (legitimate Google infrastructure) |
| Anti-spam engines flag known phishing infrastructure | Appears as a routine calendar notification |
| Requires a clickable malicious link | No link needed — entire payload is in the event description |

This is a textbook example of **abusing a trusted platform's legitimate notification system** rather than building dedicated phishing infrastructure — a pattern increasingly common as traditional email phishing gets caught more reliably by mail filters.

---

## Sample Comparison

| # | Date | Brand Impersonated | Amount Claimed | Sender Domain | Phone Number(s) |
|---|------|--------------------|-----------------|----------------|------------------|
| 1 | Jun 3 | Geek Squad | $360.22 | nickmin.com | (808) 748-1467 / (805) 303-0426 |
| 2 | Jun 3 | Norton 365 | $332.00 | kraglist.com | (828) 203-7942 / (828) 271-2063 |
| 3 | Jun 4 | McAfee ("Mac fee Security") | $548.56 | euramark.com | (805) 303-0425 |
| 4 | Jun 8 | Geek Squad | $592.24 | shxibz.com | (808) 721-3196 / (808) 909-1648 |

*(A fifth, near-duplicate Geek Squad sample was also received but omitted here for brevity — same pattern.)*

### Header Analysis (representative sample)

```
Sender: Google Calendar <calendar-notification@google.com>
From: [Attacker name] <[random]@[random-domain].com>
Reply-To: [same random address]
DKIM: pass (google.com), pass ([domain]-com.20251104.gappssmtp.com)
SPF: none (domain of [domain].com does not designate permitted sender hosts)
DMARC: unknown
```

The sender domains (`nickmin.com`, `kraglist.com`, `euramark.com`, `shxibz.com`) all use the **Google Workspace gappssmtp.com signing pattern**, confirming each was registered as a throwaway Google Workspace tenant — likely automated, low-cost setup, discarded after a short burn window.

---

## Indicators of Compromise (IOCs)

| Indicator | Type | Context / Notes |
| :--- | :--- | :--- |
| `nickmin.com` | Domain | Throwaway Google Workspace tenant (gappssmtp) — Geek Squad lure |
| `kraglist.com` | Domain | Throwaway Google Workspace tenant (gappssmtp) — Norton 365 lure |
| `euramark.com` | Domain | Throwaway Google Workspace tenant (gappssmtp) — McAfee lure |
| `shxibz.com` | Domain | Throwaway Google Workspace tenant (gappssmtp) — Geek Squad lure |
| `+1 (808) 748-1467` | Phone (VoIP) | Vishing endpoint (Geek Squad lure, sample 1) |
| `+1 (805) 303-0426` | Phone (VoIP) | Vishing endpoint (Geek Squad lure, sample 1 — sequential to `.0425`) |
| `+1 (805) 303-0425` | Phone (VoIP) | Vishing endpoint (McAfee lure, sample 3) |
| `+1 (828) 203-7942` | Phone (VoIP) | Vishing endpoint (Norton lure, sample 2) |
| `+1 (828) 271-2063` | Phone (VoIP) | Vishing endpoint (Norton lure, sample 2) |
| `+1 (808) 721-3196` | Phone (VoIP) | Vishing endpoint (Geek Squad lure, sample 4) |
| `+1 (808) 909-1648` | Phone (VoIP) | Vishing endpoint (Geek Squad lure, sample 4) |
| `a5e11c0e-ed84-43a5-9759-4a2ead308ea7` | String (UUID) | Decoy "Activation Key" used in payload body for false legitimacy |
| `10a86da0-1cf4-4459-90fc-0e5e1f668c09` | String (UUID) | Decoy "Transaction Key" used in payload body |
| `6555cd8e-384c-402a-92b7-3c2f2d20d7b1` | String (UUID) | Decoy "Access ID" used in payload body |
| `97394def-f48c-4beb-a999-4bb8eb284b64` | String (UUID) | Decoy "Verification Signature" used in payload body |

---

## Campaign Correlation — Why This Is One Actor, Not Coincidence

Three independent signals point to a single operator running multiple parallel campaigns rather than unrelated spam:

1. **Phone number reuse with digit rotation** — `(805) 303-0425` and `(805) 303-0426` appear across different brand impersonations, differing only in the last digit. This is consistent with VoIP burner numbers provisioned in sequential blocks.

2. **Identical HTML/CSS template structure** — all five emails share the exact same Google Calendar HTML scaffold (font declarations, RSVP button styling, footer text), indicating a single templating system generating all variants.

3. **Consistent pretext formula** — every email follows the same structure: fake transaction ID → fake amount (~$300–600 range, low enough to seem plausible, high enough to motivate a call) → fake "verification signature" → support phone number. Only the impersonated brand name changes.

4. **Non-native English artifacts** — phrases like *"Beloved,"* and *"Grateful always,,"* (double comma) appear as salutations, inconsistent with how a real US-based support team would write.

---

## Attacker's Likely Endgame (Vishing Flow)

Since no malicious link is present, the attack chain depends entirely on the phone call:

1. Victim sees a large, unexpected charge and panics
2. Victim calls the "support" number to dispute/cancel
3. A live operator (or scripted IVR) answers, posing as the named brand's support team
4. Operator convinces victim to install remote access software (e.g., AnyDesk, TeamViewer) to "process a refund"
5. Once remote access is granted, the attacker can exfiltrate banking credentials, install further malware, or directly manipulate the victim's online banking session to make it look like an "accidental overpayment" requiring a wire transfer back

This is a well-documented pattern in tech-support scam fraud, frequently targeting less tech-savvy users (often older demographics), though the spray-and-pray nature of this campaign suggests no targeting — it's volume-based.

---

## Detection & Defense Recommendations

For a SOC monitoring an organization's Google Workspace environment:

- **Flag calendar invites from external domains with a low sender reputation/age**, especially where `Reply-To` differs from the apparent sending identity
- **Correlate phone numbers in calendar event descriptions against known scam number databases** (community-reported, e.g., via abuse feeds)
- **User awareness training** should explicitly cover calendar invite abuse — most phishing training focuses on email links/attachments and misses this vector entirely
- Since Google does not currently offer granular controls to block calendar invites from unknown external senders at the consumer level, the most effective mitigation is **recipient education**: legitimate billing issues are never resolved by calling a number found inside an unsolicited calendar invite

---

## Analyst Notes

This analysis demonstrates correlation across multiple low-severity individual events to identify a coordinated campaign — a core SOC/threat hunting skill: a single instance of this email might be dismissed as routine spam, but pattern recognition across several instances reveals organized, ongoing abuse of trusted infrastructure (Google Calendar) for social engineering at scale.
