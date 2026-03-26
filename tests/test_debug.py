from app import analyze_password

r = analyze_password("password1A")
print(f"Score: {r['score']}")
print(f"Level: {r['level']}")
print(f"is_common: {r['is_common']}")
print(f"has_symbol: {r['criteria']['has_symbol']}")
print(f"Patterns: {[p['type'] for p in r['patterns']]}")
