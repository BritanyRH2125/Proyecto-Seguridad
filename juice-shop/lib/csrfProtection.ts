
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

// GU-02: Clave secreta aleatoria utilizada para firmar los tokens CSRF.
// Se genera una vez al iniciar el servidor.
const csrfSecret = randomBytes(32)

// GU-02: Genera una firma HMAC-SHA256 vinculada a la sesión.
// Esto impide que otro usuario fabrique un token válido.
function signToken (nonce: string, sessionToken: string): string {
  return createHmac('sha256', csrfSecret)
    .update(`${sessionToken.length}:${sessionToken}:${nonce}`)
    .digest('hex')
}

// GU-02: Crea un token CSRF con un valor aleatorio y su firma.
// El token se incorpora al formulario de actualización del perfil.
export function generateCsrfToken (sessionToken: string): string {
  const nonce = randomBytes(32).toString('hex')
  return `${nonce}.${signToken(nonce, sessionToken)}`
}

// GU-02: Comprueba que el token tenga un formato válido y que
// su firma corresponda a la sesión del usuario autenticado.
export function validateCsrfToken (
  csrfToken: unknown,
  sessionToken: string
): boolean {
  if (typeof csrfToken !== 'string') return false

  const parts = csrfToken.split('.')
  if (parts.length !== 2) return false

  const [nonce, signature] = parts

  // GU-02: Rechazar tokens manipulados o con formato incorrecto.
  if (!/^[a-f0-9]{64}$/.test(nonce) ||
      !/^[a-f0-9]{64}$/.test(signature)) {
    return false
  }

  const expectedSignature = signToken(nonce, sessionToken)

  // GU-02: Comparar las firmas en tiempo constante
  // para reducir filtraciones de información por tiempo.
  return timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  )
}
