// Provably fair verifier for happyending.com pack openings (algorithm "hmac-sha256-stream-v1").
// Runs entirely in your browser (or Node 20+). It makes no network requests.

const encoder = new TextEncoder()
const toHex = (buffer) => Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('')

// Step 0: the server seed hash shown before you played must be SHA-256 of the revealed
// server seed, hashed as text. If it matches, the seed was fixed before your spin.
export async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest('SHA-256', encoder.encode(text)))
}

const TICKET_SPACE = 1_000_000
// The largest multiple of 1,000,000 below 2^32. Numbers at or above it are skipped so that
// every ticket from 1 to 1,000,000 is exactly equally likely.
const LIMIT = 4_294_000_000

export async function computeTicket({ serverSeed, clientSeed, nonce }) {
  // Step 1: HMAC-SHA256 with the server seed as the key and "clientSeed:nonce:0" as the message.
  // If more random bytes are ever needed, the last number counts up: ":1", ":2", ...
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(serverSeed), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const block = (i) => crypto.subtle.sign('HMAC', key, encoder.encode(`${clientSeed}:${nonce}:${i}`))

  const first = await block(0)
  for (let i = 0, bytes = first; ; bytes = await block(++i)) {
    const view = new DataView(bytes)
    // Step 2: read the output 4 bytes at a time as a big-endian whole number (0 to 4,294,967,295).
    for (let offset = 0; offset < 32; offset += 4) {
      const value = view.getUint32(offset, false)
      // Step 3: keep the first number below the limit; the ticket is its remainder plus 1.
      if (value < LIMIT) {
        return { message: `${clientSeed}:${nonce}:0`, hmacHex: toHex(first), ticket: (value % TICKET_SPACE) + 1 }
      }
    }
  }
}
// Step 4 happens on the pack page: each item owns a range of tickets, and your ticket's range is your item.
