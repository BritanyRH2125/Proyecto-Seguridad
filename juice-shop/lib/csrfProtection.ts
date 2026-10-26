import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const csrfSecret = randomBytes(32)

function signToken (nonce: string, sessionToken: string): string {
  return createHmac('sha256', csrfSecret)
    .update(`${sessionToken.length}:${sessionToken}:${nonce}`)
    .digest('hex')
}

export function generateCsrfToken (sessionToken: string): string {
  const nonce = randomBytes(32).toString('hex')
  return `${nonce}.${signToken(nonce, sessionToken)}`
}

export function validateCsrfToken (
  csrfToken: unknown,
  sessionToken: string
): boolean {
  if (typeof csrfToken !== 'string') return false

  const parts = csrfToken.split('.')
  if (parts.length !== 2) return false

  const [nonce, signature] = parts

  if (!/^[a-f0-9]{64}$/.test(nonce) ||
      !/^[a-f0-9]{64}$/.test(signature)) {
    return false
  }

  const expectedSignature = signToken(nonce, sessionToken)

  return timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  )
}
