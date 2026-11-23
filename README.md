# Provably fair verifier

An independent, open-source page for checking happyending.com pack openings:
**https://dbd-net.github.io/pf-verifier/**

It runs entirely in your browser. It makes no network requests, loads no outside scripts, and
values passed in the link ride in the `#fragment`, which browsers never send to a server.
The whole algorithm is in [`verify.js`](verify.js).

## What it checks

1. **The seed was fixed before you played.** SHA-256 of the revealed server seed (hashed as text)
   must equal the server seed hash you were shown before the spin.
2. **The ticket follows from the seeds.** With the server seed as the key, compute
   `HMAC-SHA256("clientSeed:nonce:0")`.
3. Read the output 4 bytes (8 hex characters) at a time as a whole number. Keep the first one
   below 4,294,000,000; your ticket is that number's remainder after dividing by 1,000,000, plus 1.
   (Skipping larger numbers keeps every ticket exactly equally likely. It happens about once in
   4,400 spins. If all 8 numbers in the output are skipped, compute the HMAC again with `:1` at
   the end instead of `:0`, and so on.)
4. Each item in the pack owns a range of tickets. The range your ticket falls in is your item;
   the round's proof page on happyending.com shows that range.

## Check it with any tool

You don't have to trust this page either. With any online SHA-256 and HMAC-SHA256 calculator:

1. SHA-256 the server seed. Compare with the server seed hash.
2. HMAC-SHA256 with the server seed as the key and `clientSeed:nonce:0` as the message.
3. Take the first 8 hex characters of the output and convert them to decimal.
4. If that number is below 4,294,000,000, your ticket is `(number mod 1,000,000) + 1`.
   Otherwise use the next 8 hex characters.

Example: server seed `abc`, client seed `x`, nonce `0` → HMAC output starts `7fbd9e51`
→ 2,143,133,265 → ticket **133,266**.

## Tests

```
node --test
```
