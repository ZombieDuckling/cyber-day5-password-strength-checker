# Day 5: basic password strength checker (Python CLI)

This is a beginner-friendly cybersecurity portfolio project for Josh (day 5 of
7). You run a local CLI tool that scores a password and explains exactly why it
received that score.

The goal is educational: understand strong-password basics and build a simple,
explainable checker. This project does not crack passwords, attack systems, or
bypass controls.

## What this project does

The script evaluates a password with a transparent score out of 100:

- Length score (longer is better)
- Character variety score (lower/upper/digits/symbols)
- Rough entropy estimate score
- Penalties for common weak patterns (common words, sequences, repetition)

It then prints:

- Numeric score and rating (`Weak`, `Moderate`, `Strong`)
- A line-by-line explanation of scoring decisions
- Practical improvement tips

## Quick research and key learning points

I used these references to shape the approach:

1. NIST SP 800-63B / 63-4 guidance on memorized secrets
   - URL: https://pages.nist.gov/800-63-4/sp800-63b/secrets/
2. OWASP Authentication Cheat Sheet
   - URL: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
3. Dropbox zxcvbn article (and linked USENIX paper)
   - URL: https://dropbox.tech/security/zxcvbn-realistic-password-strength-estimation

Key takeaways I applied here:

- Prioritize password length over rigid complexity rules.
- Permit broad character usage and avoid overfitting to one policy.
- Penalize obvious predictable patterns (for example `1234`, `abcd`, repeated
  chunks).
- Keep scoring explainable for beginners so users learn what to improve.
- Treat this checker as educational, not as a replacement for mature production
  controls and blocklist systems.

## Requirements

You need Python 3.9+.

## How to run

From this folder:

1. Run with interactive hidden input:
   - `python3 password_strength_checker.py`
2. Or pass a password directly:
   - `python3 password_strength_checker.py "MyTestPass123!"`

Optional:

- Show the real password in output (default masks it):
  - `python3 password_strength_checker.py "MyTestPass123!" --show-password`

## Example output

```text
Password strength report
--------------------------
Password: ***************
Score:    78/100
Rating:   Moderate

Why this score:
  - +30: Length is 12-15 characters (strong).
  - +25: Character variety (4/4 categories used).
  - +18: Estimated entropy is 63.2 bits (good).

How to improve:
  - Use at least 16 characters.
  - Avoid predictable sequences like '1234' or 'abcd'.
```

## Ethical and legal use

Use this tool only for defensive learning and personal security hygiene. Do not
use it to target accounts, evade controls, or perform unauthorized activity.

## Next steps

Good follow-ups for day 6+:

- Add unit tests (`pytest`) for score edge cases.
- Add support for checking against a larger local weak-password list.
- Add optional JSON output for automation and portfolio demos.
