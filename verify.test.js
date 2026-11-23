import assert from 'node:assert/strict'
import { test } from 'node:test'
import { computeTicket, sha256Hex } from './verify.js'

const B2 = 'b2'.repeat(32)

test('golden vectors give the expected tickets', async () => {
  assert.equal((await computeTicket({ serverSeed: B2, clientSeed: 'player-seed-1', nonce: 7 })).ticket, 121837)
  assert.equal((await computeTicket({ serverSeed: 'abc', clientSeed: 'x', nonce: 0 })).ticket, 133266)
  // The first 4 bytes are too large and must be skipped, not folded.
  assert.equal((await computeTicket({ serverSeed: 'abc', clientSeed: 'x', nonce: 72 })).ticket, 995102)
})

test('reports the message and HMAC output of block 0', async () => {
  const r = await computeTicket({ serverSeed: B2, clientSeed: 'player-seed-1', nonce: 7 })
  assert.equal(r.message, 'player-seed-1:7:0')
  assert.equal(r.hmacHex, 'd1fe92ac7237d748d59868cc61d6b85e08a23b9ba21a0c4f18b3f3d63d580c7c')
})

test('hashes the server seed as text', async () => {
  assert.equal(await sha256Hex(B2), '92e18130ebb234a4757b877d7ba5bdc1a973140fe662a9bff9751c7ca38b5b2f')
})
