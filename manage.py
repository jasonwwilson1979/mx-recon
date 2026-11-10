#!/usr/bin/env python
"""MX-RECON — Email Security & DNS Forensics Console (Django)."""
import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mx_recon.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Ensure it is installed and available on "
            "PYTHONPATH, and that the virtualenv is activated."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
