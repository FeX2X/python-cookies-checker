# Advanced Cookies Checker

A Python-based cookie auditing utility designed to parse, normalize, inspect, and validate Netscape-format cookie files.

## Target Website
#**some time if u see error or block change you ip**
**interested to make bank-cookies any ida dm me**
- **Site** — https://www.loaded.com/ , https://primevideo.com

## Features

- Netscape cookie file parsing
- Cookie record normalization
- Combined cookie log processing
- Cookie group identification
- HTTP session handling
- Target website response inspection
- Structured audit reporting
- Organized output files

## Technologies

- Python 3
- curl_cffi
- fake-useragent
- http.cookiejar
- tempfile

## Run
1. Run `cookies-grabber.py` using a single domain (e.g., `domain.com`) from the log files.
   Supported formats are listed below the image
<img width="1895" height="525" alt="image" src="https://github.com/user-attachments/assets/22b72e15-5a04-4cbe-b7bd-f76d648c4027" />

2. Run `advanced-cookies-checker.py` using the generated `cookies.txt` file in the same directory.

```text
Domain-specific authorized log files
              |
              v
     cookies-grabber.py
              |
              v
          cookies.txt
              |
              v
 advanced-cookies-checker.py
              |
              v
       Audit Results
              |
              v
     valid_cookies.txt
```

## Disclaimer

For educational purposes and authorized security testing only. Use only cookie data and target accounts you own or have explicit permission to test. Never access another person's account or session.
