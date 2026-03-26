"""
Keyboard Sequences for Pattern Detection
Extracted from app.py for maintainability and reusability
Last updated: 2025-01-15

Contains common keyboard walks and sequential patterns that
users typically use when creating passwords.
"""

KEYBOARD_SEQUENCES = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "1234567890", "0987654321", "abcdefghij", "abcdef",
    "qweasdzxc", "!@#$%^&*()",
]

__all__ = ["KEYBOARD_SEQUENCES"]
