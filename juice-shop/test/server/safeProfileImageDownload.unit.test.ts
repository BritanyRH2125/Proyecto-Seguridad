
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  isAllowedProfileImageIp,
  validateProfileImageUrl
} from '../../lib/safeProfileImageDownload'

describe('GU-05: Protección SSRF en imágenes de perfil', () => {
  it('bloquea direcciones loopback', () => {
    assert.equal(isAllowedProfileImageIp('127.0.0.1'), false)
  })

  it('bloquea direcciones privadas', () => {
    assert.equal(isAllowedProfileImageIp('192.168.1.1'), false)
    assert.equal(isAllowedProfileImageIp('10.0.0.1'), false)
    assert.equal(isAllowedProfileImageIp('172.16.0.1'), false)
  })

  it('bloquea localhost', () => {
    assert.throws(() => validateProfileImageUrl('http://localhost:8085/test.txt'))
  })

  it('bloquea protocolos no permitidos', () => {
    assert.throws(() => validateProfileImageUrl('file:///etc/passwd'))
  })

  it('bloquea credenciales incluidas en la URL', () => {
    assert.throws(() => validateProfileImageUrl('https://usuario:clave@example.com/imagen.png'))
  })

  it('permite validar inicialmente una URL HTTPS pública', () => {
    const url = validateProfileImageUrl('https://example.com/imagen.png')
    assert.equal(url.hostname, 'example.com')
  })
})
