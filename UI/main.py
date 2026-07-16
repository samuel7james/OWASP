import os
import sys


def _configure_utf8_stdio():
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


_configure_utf8_stdio()

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root not in sys.path:
    sys.path.append(root)
    sys.path.append(os.path.join(root, "Logic"))
    sys.path.append(os.path.join(root, "Logic", "Recon"))
    sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
    sys.path.append(os.path.join(root, "Data"))

import csrf_scan
import sqli_scan
import xss_scan

BANNER = r"""
      ___           _              _   _               _   _
     / _ \         | |            | | | |             | | (_)
    / /_\ \  _   _ | |_  ___      | |_| | _   _  _ __ | |_  _  _ __    __ _
   / / _ \ \| | | || __|/ _ \     |  _  || | | || '_ \| __|| || '_ \  / _` |
  / / ___ \ \ |_| || |_| (_) |    | | | || |_| || | | || |_ | || | | || (_| |
 /_/ /   \_\ \__,_| \__|\___/     \_| |_/ \__,_||_| |_| \__||_||_| |_| \__, |
                                                                        __/ |
                                                                       |___/
"""


def display_banner():
    print(BANNER)


def main():
    display_banner()
    try:
        while True:
            print("\n" + "=" * 40)
            print("       SCAN MENU")
            print("=" * 40)
            print("1) SQLi scan")
            print("2) XSS scan")
            print("3) CSRF scan")
            print("4) Exit")
            print("=" * 40)

            option = input("Enter option (1-4): ").strip()

            if option == "1":
                print("[*] Running SQLi Scan...")
                sqli_scan.main()
            elif option == "2":
                print("[*] Running XSS Scan...")
                xss_scan.main()
            elif option == "3":
                print("[*] Running CSRF Scan...")
                csrf_scan.main()
            elif option == "4":
                print("Exiting")
                sys.exit(0)
            else:
                print("[-] Invalid option. Choose 1-4.")
    except KeyboardInterrupt:
        print("\nExiting")
        sys.exit(0)


if __name__ == "__main__":
    main()
