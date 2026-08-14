# pwaudit

Two small utilities that kept living in random one-off scripts on my
machine, so I finally put them in one place: a password strength checker,
and a hash format identifier for when I find a credential dump and need to
figure out what I'm looking at before deciding whether it's even worth
attacking.

Standard library only.

## check - password strength

```
python3 pwaudit.py check "Summer2023!"
```

```
password : 'Summer2023!'
rating   : strong  (~72.1 bits of entropy, rough estimate)
issues   : none found
```

Flags: length under 8, missing character classes, membership in a small
embedded common-password list, keyboard walks (`qwerty`, `asdf`),
sequential runs (`abcd`, `1234`), and repeated-character runs (`aaaa`).

The entropy number is a rough pool-size estimate (`length * log2(charset
size)`), not a formal crack-time calculation - treat the rating word as the
useful part, not the exact bit count.

## identify - hash format guesser

```
python3 pwaudit.py identify '$2b$12$KIXQ4t1y5z...'
python3 pwaudit.py identify 5f4dcc3b5aa765d61d8327deb882cf99
```

Matches common patterns: bcrypt, md5crypt/sha256crypt/sha512crypt (Unix
`$1$`/`$5$`/`$6$` prefixes), argon2, pbkdf2, and bare hex digests by length
(MD5/NTLM at 32 chars, SHA-1 at 40, SHA-256 at 64, SHA-512 at 128, etc).
32-char hex is inherently ambiguous between MD5 and NTLM since they're the
same length - you need context (Windows vs Unix source) to tell them apart.

## hash - quick one-off hashing

```
python3 pwaudit.py hash "some string" --algo sha256
```

Just a thin wrapper around `hashlib` for when I don't want to open a Python
shell for one hash.

## Limitations

The common-password list is intentionally small (a few dozen entries) - use
a real wordlist for anything serious. The hash identifier is pattern
matching, not detection; salted/keyed formats without a recognizable
prefix will come back with no match, which is expected.

## License

MIT, see LICENSE.
