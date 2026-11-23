"""Command-line interface for the password strength checker."""

import sys
from getpass import getpass

from checker import analyse
from generator import (
    generate_passphrase,
    generate_password,
    passphrase_entropy,
    password_entropy,
)

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


def ask_number(prompt: str, default: int, low: int, high: int) -> int:
    """Ask for a whole number in a range. Pressing Enter uses the default."""
    text = input(f"{prompt} ({low}-{high}, Enter for {default}): ").strip()
    if text == "":
        return default
    if text.isdigit() and low <= int(text) <= high:
        return int(text)
    print(f"Not a valid number, using {default}.")
    return default


def check_passwords(read) -> None:
    print("\nPress Enter on an empty line to go back.")
    while True:
        password = read("Enter a password to check: ")
        if password == "":
            return
        show_report(password)


def make_password() -> None:
    length = ask_number("Password length", 16, 8, 64)
    password = generate_password(length)
    print(f"\nGenerated password: {password}")
    print(f"Randomness: about {password_entropy(length)} bits")
    show_report(password)


def make_passphrase() -> None:
    words = ask_number("Number of words", 6, 4, 10)
    phrase = generate_passphrase(words)
    print(f"\nGenerated passphrase: {phrase}")
    print(f"Real randomness: {passphrase_entropy(words)} bits "
          "(from a 256-word list, so 8 bits per word)")
    print("Tip: more words means stronger. 8 or more is a very good choice.\n")


def main() -> None:
    visible = "--show" in sys.argv
    read = input if visible else getpass

    print("=== Password Strength Checker ===")
    if visible:
        print("Visible mode: what you type will show on screen.")
    else:
        print("Typed passwords are hidden. Nothing is stored or sent anywhere.")

    while True:
        print("\n1. Check a password")
        print("2. Generate a random password")
        print("3. Generate a passphrase")
        print("4. Quit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            check_passwords(read)
        elif choice == "2":
            make_password()
        elif choice == "3":
            make_passphrase()
        elif choice == "4":
            print("Goodbye.")
            break
        else:
            print("Please enter 1, 2, 3 or 4.")


if __name__ == "__main__":
    main()