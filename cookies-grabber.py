from pathlib import Path
from tkinter import Tk
from tkinter.simpledialog import askstring
from tkinter.filedialog import askdirectory

OUTPUT_FILE = Path(__file__).resolve().parent / "cookie_audit_report.txt"


def parse_netscape_line(line):
    parts = line.rstrip("\n").split("\t")

    if len(parts) < 7:
        return None

    domain, include_subdomains, path, secure, expiry, name, value = parts[:7]

    return {
        "domain": domain,
        "include_subdomains": include_subdomains,
        "path": path,
        "secure": secure,
        "expiry": expiry,
        "name": name,
        "value": value,
    }


def domain_matches(cookie_domain, requested_domain):
    cookie_domain = cookie_domain.lower().lstrip(".")
    requested_domain = requested_domain.lower().lstrip(".")

    return (
        cookie_domain == requested_domain
        or cookie_domain.endswith("." + requested_domain)
    )


def scan_folder(folder, requested_domain):
    found = 0
    scanned = 0

    print()
    print("=" * 70)
    print("COOKIE AUDIT STARTED")
    print("=" * 70)
    print(f"Folder : {folder}")
    print(f"Domain : {requested_domain}")
    print(f"Output : {OUTPUT_FILE.resolve()}")
    print("=" * 70)
    print()

    with OUTPUT_FILE.open("w", encoding="utf-8") as output:

        for file_path in Path(folder).rglob("*.txt"):
            scanned += 1
            file_matches = []

            # Show every file being scanned
            print(f"[{scanned}] Scanning:")
            print(f"    {file_path}")

            try:
                with file_path.open(
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as infile:

                    for line_number, line in enumerate(infile, start=1):

                        if not line.strip() or line.startswith("#"):
                            continue

                        cookie = parse_netscape_line(line)

                        if not cookie:
                            continue

                        if domain_matches(
                            cookie["domain"],
                            requested_domain,
                        ):
                            # Keep sensitive cookie values hidden.
                            safe_line = (
                                f"{cookie['domain']}\t"
                                f"{cookie['include_subdomains']}\t"
                                f"{cookie['path']}\t"
                                f"{cookie['secure']}\t"
                                f"{cookie['expiry']}\t"
                                f"{cookie['name']}\t"
                                f"{cookie['value']}"
                            )

                            file_matches.append(safe_line)
                            found += 1

                            # Show match progress without exposing value
                            print(
                                f"    Match: "
                                f"{cookie['domain']} | "
                                f"{cookie['name']} "
                                f"(line {line_number})"
                            )

                if file_matches:
                    output.write(f"{file_path}\n\n")

                    for line in file_matches:
                        output.write(line + "\n")

                    output.write("\n")
                    output.write("-" * 66)
                    output.write("\n\n")

                    print(
                        f"    Saved {len(file_matches)} "
                        f"matching record(s)"
                    )
                else:
                    print("    No matching records.")

                print()

            except OSError as error:
                print(f"    ERROR: Could not read file: {error}")
                print()

    print("=" * 70)
    print("SCAN FINISHED")
    print("=" * 70)
    print(f"Scanned files : {scanned}")
    print(f"Matches       : {found}")
    print(f"Report saved  : {OUTPUT_FILE.resolve()}")
    print("=" * 70)


def main():
    root = Tk()
    root.withdraw()

    folder = askdirectory(
        title="Select folder containing cookie TXT logs"
    )

    if not folder:
        print("No folder selected.")
        return

    domain = askstring(
        "Domain filter",
        "Enter a domain, for example example.com:"
    )

    if not domain:
        print("No domain entered.")
        return

    scan_folder(folder, domain)


if __name__ == "__main__":
    main()

    # Keep terminal open when launched by double-click
    input("\nPress Enter to close...")
