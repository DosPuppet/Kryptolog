"""Security primitives: authorization decisions and untrusted-input guards.

Kept separate from the routers so a rule lives in exactly one place. KRY-001
happened because the grant-expiry rule was duplicated between the listing
endpoints and the chunk endpoints, and only the listings got it right.
"""
