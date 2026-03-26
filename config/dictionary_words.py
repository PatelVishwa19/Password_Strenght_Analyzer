"""
Dictionary Words for Pattern Detection
Extracted from app.py for maintainability and reusability
Last updated: 2025-01-15

Contains common English dictionary words and names that are frequently
used in passwords and reduce password entropy significantly.
"""

DICTIONARY_WORDS = {
    "password", "dragon", "master", "monkey", "shadow", "sunshine",
    "princess", "welcome", "football", "baseball", "soccer", "batman",
    "superman", "michael", "charlie", "donald", "login", "admin",
    "iloveyou", "letmein", "trustno", "access", "hello", "summer",
    "winter", "spring", "autumn", "flower", "house", "computer",
    "internet", "network", "security", "freedom", "starwars",
}

__all__ = ["DICTIONARY_WORDS"]
