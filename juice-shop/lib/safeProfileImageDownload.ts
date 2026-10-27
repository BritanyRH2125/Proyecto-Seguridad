import dns from 'node:dns'
import { BlockList, isIP } from 'node:net'
import { Agent, request } from 'undici'
import fileType from 'file-type'

const MAX_IMAGE_BYTES = 2 * 1024 * 1024
const blocked = new BlockList()

// GU-05: Excluir redes internas, reservadas y no públicas.
const blockedRanges: Array<[string, number]> = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4]
]

for (const [address, prefix] of blockedRanges) {
  blocked.addSubnet(address, prefix, 'ipv4')
}

export function isAllowedProfileImageIp (address: string): boolean {
  // Política conservadora: únicamente IPv4 pública.
  // IPv6 y direcciones IPv4 mapeadas a IPv6 se rechazan.
  return isIP(address) === 4 && !blocked.check(address, 'ipv4')
}

export function validateProfileImageUrl (value: string): URL {
  const url = new URL(value)

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('GU-05: protocolo no permitido')
  }

  if (url.username || url.password) {
    throw new Error('GU-05: credenciales en URL no permitidas')
  }

  const hostname = url.hostname.replace(/^\[|\]$/g, '')

  if (hostname.toLowerCase() === 'localhost' ||
      hostname.toLowerCase().endsWith('.localhost')) {
    throw new Error('GU-05: destino local bloqueado')
  }

  if (isIP(hostname) && !isAllowedProfileImageIp(hostname)) {
    throw new Error('GU-05: dirección IP no pública')
  }

  return url
}

const dispatcher = new Agent({
  connect: {
    lookup: (hostname, options, callback) => {
      dns.lookup(hostname, { all: true }, (error, addresses) => {
        if (error) {
          callback(error, [])
          return
        }

        // GU-05: Rechazar cualquier respuesta DNS vacía
        // o que contenga direcciones privadas, locales o IPv6.
        if (addresses.length === 0 ||
            addresses.some(({ address }) => !isAllowedProfileImageIp(address))) {
          callback(new Error('GU-05: resolución DNS hacia IP no pública'), [])
          return
        }

        // Conservar el formato que Node.js espera cuando
        // solicita todas las direcciones mediante DNS.
        if (options.all) {
          callback(null, addresses)
        } else {
          const selected = addresses[0]
          callback(null, selected.address, selected.family)
        }
      })
    },
    timeout: 5000
  }
})

export async function downloadSafeProfileImage (
  value: string
): Promise<{ buffer: Buffer, extension: string }> {
  const url = validateProfileImageUrl(value)

  const response = await request(url.toString(), {
    dispatcher,
    maxRedirections: 0,
    headersTimeout: 5000,
    bodyTimeout: 5000,
    signal: AbortSignal.timeout(10000)
  })

  // GU-05: Nunca seguir redirecciones hacia destinos internos.
  if (response.statusCode !== 200) {
    response.body.destroy()
    throw new Error('GU-05: respuesta HTTP no permitida')
  }

  const contentLength = Number(response.headers['content-length'])

  if (Number.isFinite(contentLength) &&
      contentLength > MAX_IMAGE_BYTES) {
    response.body.destroy()
    throw new Error('GU-05: imagen demasiado grande')
  }

  const chunks: Buffer[] = []
  let size = 0

  for await (const chunk of response.body) {
    const bytes = Buffer.from(chunk)
    size += bytes.length

    if (size > MAX_IMAGE_BYTES) {
      response.body.destroy()
      throw new Error('GU-05: límite de descarga excedido')
    }

    chunks.push(bytes)
  }

  const buffer = Buffer.concat(chunks)
  const detected = await fileType.fromBuffer(buffer)

  const extensions: Record<string, string> = {
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/gif': 'gif',
    'image/webp': 'webp'
  }

  const extension = detected && extensions[detected.mime]

  if (!extension) {
    throw new Error('GU-05: contenido no es una imagen permitida')
  }

  return { buffer, extension }
}
