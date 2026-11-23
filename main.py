"""Command-line interface for the password strength checker."""

import sys
from getpass import getpass

from checker import analyse

BAR_WIDTH = 30


def bar(score: int) -> str:
    filled = round(score / 100 * BAR_WIDTH)
    return "[" + "#" * filled + "." * (BAR_WIDTH - filled) + "]"


def show_report(password: str) -> None:
    result = analyse(password)
    print()
    print(f"Score:   {result.score}/100  {bar(result.score)}  {result.rating}")
    print(f"Entropy: {result.bits} bits")
    print(f"Guessing time (offline attack, fast hardware): {result.crack_time}")

    if result.issues:
        print("\nProblems found:")
        for issue in result.issues:
            print(f"  - {issue}")
    else:
        print("\nNo problems found.")

    if result.suggestions:
        print("\nHow to improve it:")
        for suggestion in result.suggestions:
            print(f"  - {suggestion}")
    print()


def main() -> None:
    visible = "--show" in sys.argv
    read = input if visible else getpass

    print("=== Password Strength Checker ===")
    if visible:
        print("Visible mode: what you type will show on screen.")
    else:
        print("Your typing is hidden. Nothing is stored or sent anywhere.")
    print("Press Enter on an empty line to quit.\n")

    while True:
        password = read("Enter a password to check: ")
        if password == "":
            print("Goodbye.")
            break
        show_report(password)


if __name__ == "__main__":
    main()