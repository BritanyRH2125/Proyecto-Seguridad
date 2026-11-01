
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
    serializeAuditEvent,
    createAuditWriter
} from '../../lib/auditLogger'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

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

    void it('debe neutralizar caracteres de control y limitar la longitud de los campos', () => {
        const line = serializeAuditEvent({
            event: 'security.' + 'X'.repeat(500),
            outcome: 'failure',
            severity: 'warning',
            traceId: 'trace-123\r\nEVENTO_FALSO'
        })

        const record = JSON.parse(line)

        assert.ok(record.event.length <= 120)
        assert.doesNotMatch(record.traceId, /[\r\n]/)
        assert.equal(line.trimEnd().split('\n').length, 1)
    })

    void it('debe redactar secretos y conservar detalles no sensibles', () => {
        const line = serializeAuditEvent({
            event: 'security.test',
            outcome: 'failure',
            severity: 'warning',
            traceId: 'trace-prueba-002',
            details: {
                password: 'ClaveFicticia123!',
                authorization: 'Bearer token-simulado',
                cookie: 'sid=sesion-ficticia',
                reason: 'invalid_credentials'
            }
        })

        const record = JSON.parse(line)

        assert.equal(record.details.password, '[REDACTED]')
        assert.equal(record.details.authorization, '[REDACTED]')
        assert.equal(record.details.cookie, '[REDACTED]')
        assert.equal(record.details.reason, 'invalid_credentials')

        assert.doesNotMatch(
            line,
            /ClaveFicticia123!|token-simulado|sesion-ficticia/
        )
    })


    void it('debe persistir eventos independientes en formato JSON Lines', async () => {
        const testDirectory = mkdtempSync(join(tmpdir(), 'audit-la01-'))

        try {
            const filePath = join(testDirectory, 'security-audit.log')
            const writeEvent = createAuditWriter(filePath)

            await writeEvent({
                event: 'security.test',
                outcome: 'success',
                severity: 'info',
                traceId: 'trace-001'
            })

            await writeEvent({
                event: 'security.test',
                outcome: 'failure',
                severity: 'warning',
                traceId: 'trace-002'
            })

            const content = readFileSync(filePath, 'utf8')
            const lines = content.trimEnd().split(/\r?\n/)

            assert.equal(lines.length, 2)

            const firstEvent = JSON.parse(lines[0])
            const secondEvent = JSON.parse(lines[1])

            assert.equal(firstEvent.traceId, 'trace-001')
            assert.equal(firstEvent.outcome, 'success')

            assert.equal(secondEvent.traceId, 'trace-002')
            assert.equal(secondEvent.outcome, 'failure')
        } finally {
            rmSync(testDirectory, { recursive: true, force: true })
        }
    })

})
