
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { serializeAuditEvent } from '../../lib/auditLogger'

void describe('auditLogger', () => {
  void it('debe serializar un evento de auditoría como una línea JSON válida', () => {
    const line = serializeAuditEvent({
      event: 'security.test',
      outcome: 'failure',
      severity: 'warning',
      traceId: 'trace-prueba-001'
    })

    assert.equal(typeof line, 'string')
    assert.ok(line.endsWith('\n'))

    const lines = line.trimEnd().split(/\r?\n/)
    assert.equal(lines.length, 1)

    const event = JSON.parse(line)

    assert.equal(event.event, 'security.test')
    assert.equal(event.outcome, 'failure')
    assert.equal(event.severity, 'warning')
    assert.equal(event.traceId, 'trace-prueba-001')

    assert.equal(typeof event.timestamp, 'string')
    assert.equal(
      new Date(event.timestamp).toISOString(),
      event.timestamp
    )
  })
})
