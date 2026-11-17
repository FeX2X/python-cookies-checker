# Advanced Cookies Checker

A Python-based cookie auditing utility designed to parse, normalize, inspect, and validate Netscape-format cookie files.

## Target Website

- **Loaded.com** — https://www.loaded.com/

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

## run
- run cookies-grabber.py use domin.com single domin fomr logs files
- then run advanced-cookies-checker.py with cookies.txt file same lication

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

## Disclaimer

For educational purposes and authorized security testing only. Use only cookie data and target accounts you own or have explicit permission to test. Never access another person's account or session.
