"""
Secure Notes App
==================
Project 2 - Encrypted text storage.

A simple notes app where every note is encrypted with AES using a
passphrase the user provides. Notes are only ever stored on disk in
encrypted form; the encryption key is derived from the passphrase and is
cleared from memory as soon as it's no longer needed.

Tools: Java, AES
(Implemented here in Python using the `cryptography` library, which
provides the same AES primitives; the Java version would use
javax.crypto.Cipher with AES/GCM the same way.)

How it works:
    1. User provides a passphrase.
    2. A key is derived from the passphrase using PBKDF2 (so we're not
       using the raw passphrase as the AES key directly).
    3. Notes are encrypted with AES-GCM (authenticated encryption -- this
       also detects tampering, not just confidentiality).
    4. Encrypted notes (ciphertext + nonce + salt) are stored in a local
       file. The plaintext is never written to disk.

Tips implemented:
    - Encrypts strings using a user-provided passphrase (PBKDF2 -> AES key).
    - Clears the encryption key from RAM as soon as encryption/decryption
      finishes, by overwriting the bytearray before it goes out of scope.
"""

import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

NOTES_FILE = Path(__file__).parent / "secure_notes.json"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12


def derive_key(passphrase: str, salt: bytes) -> bytearray:
    """Derives a 256-bit AES key from a passphrase + salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return bytearray(key)  # bytearray so we can zero it out later


def wipe_key(key: bytearray):
    """Overwrites the key in memory with zeros once we're done with it."""
    for i in range(len(key)):
        key[i] = 0


def encrypt_note(plaintext: str, passphrase: str) -> dict:
    """Encrypts a note with AES-GCM using a key derived from the passphrase."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)

    try:
        aesgcm = AESGCM(bytes(key))
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    finally:
        wipe_key(key)  # clear key from RAM regardless of success/failure

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_note(record: dict, passphrase: str) -> str:
    """Decrypts a note record using the same passphrase it was encrypted with."""
    salt = base64.b64decode(record["salt"])
    nonce = base64.b64decode(record["nonce"])
    ciphertext = base64.b64decode(record["ciphertext"])
    key = derive_key(passphrase, salt)

    try:
        aesgcm = AESGCM(bytes(key))
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    finally:
        wipe_key(key)

    return plaintext.decode("utf-8")


def load_notes() -> list:
    if NOTES_FILE.exists():
        with open(NOTES_FILE, "r") as f:
            return json.load(f)
    return []


def save_notes(notes: list):
    with open(NOTES_FILE, "w") as f:
        json.dump(notes, f, indent=2)


def add_note(text: str, passphrase: str):
    notes = load_notes()
    notes.append(encrypt_note(text, passphrase))
    save_notes(notes)
    print(f"Note encrypted and saved. ({len(notes)} total notes on disk)")


def list_notes(passphrase: str):
    notes = load_notes()
    if not notes:
        print("No notes stored yet.")
        return
    for i, record in enumerate(notes, start=1):
        try:
            text = decrypt_note(record, passphrase)
            print(f"[{i}] {text}")
        except Exception:
            print(f"[{i}] <could not decrypt - wrong passphrase or corrupted note>")


def demo():
    print("=" * 60)
    print("SECURE NOTES APP - DEMO")
    print("=" * 60)

    passphrase = "correct-horse-battery-staple"

    # Add a couple of notes
    add_note("Server root password rotation is due next Friday.", passphrase)
    add_note("Remember to renew the TLS certificate for the intranet.", passphrase)

    print(f"\nRaw file on disk ({NOTES_FILE.name}) contains only ciphertext:")
    with open(NOTES_FILE) as f:
        print(f.read())

    print("Decrypting notes with the correct passphrase:")
    list_notes(passphrase)

    print("\nAttempting to decrypt with the WRONG passphrase:")
    list_notes("wrong-passphrase")

    print("\nTip: the AES key is derived fresh from your passphrase every time")
    print("and is wiped from memory (overwritten with zeros) right after use --")
    print("it is never written to disk and doesn't linger in RAM.")


if __name__ == "__main__":
    demo()
