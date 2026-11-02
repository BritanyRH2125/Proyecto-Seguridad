
/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { EventEmitter } from 'node:events'
import { setImmediate as waitForAsync } from 'node:timers/promises'
import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import type { Request, Response, NextFunction } from 'express'

import { auditDataExport } from '../../lib/dataExportAudit'
import {
    getAuditTraceId,
    type AuditEventInput
} from '../../lib/auditLogger'

function createHarness(
    statusCode: number,
    writerFails = false
) {
    const req = {
        headers: {
            authorization: 'Bearer PRIVATE_TOKEN_123',
            'x-request-id': 'client-controlled-id'
        },
        body: {
            answer: 'captcha-secret',
            email: 'private@example.org'
        }
    } as unknown as Request

    const response = Object.assign(new EventEmitter(), {
        statusCode
    })

    const events: AuditEventInput[] = []
    const errorCodes: string[] = []

    const writer = mock.fn(async (event: AuditEventInput) => {
        if (writerFails) {
            throw new Error('Simulated audit storage failure')
        }

        events.push(event)
    })

    const onFailure = mock.fn((code: string) => {
        errorCodes.push(code)
    })

    const next = mock.fn()

    auditDataExport(writer, onFailure)(
        req,
        response as unknown as Response,
        next as unknown as NextFunction
    )

    return {
        req,
        response,
        events,
        errorCodes,
        next
    }
}

void describe('dataExportAudit - LA-04', () => {
    const cases: Array<{
        statusCode: number
        outcome: AuditEventInput['outcome']
        severity: AuditEventInput['severity']
    }> = [
            { statusCode: 200, outcome: 'success', severity: 'info' },
            { statusCode: 401, outcome: 'denied', severity: 'warning' },
            { statusCode: 403, outcome: 'denied', severity: 'warning' },
            { statusCode: 400, outcome: 'failure', severity: 'warning' },
            { statusCode: 500, outcome: 'failure', severity: 'error' }
        ]

    for (const { statusCode, outcome, severity } of cases) {
        void it(`should audit HTTP ${statusCode}`, () => {
            const { req, response, events, next } =
                createHarness(statusCode)

            assert.equal(next.mock.callCount(), 1)

            response.emit('finish')

            assert.deepEqual(events, [{
                event: 'data.export',
                outcome,
                severity,
                traceId: getAuditTraceId(req),
                details: {
                    httpStatus: statusCode
                }
            }])
        })
    }

    void it('should record an event only once', () => {
        const { response, events } = createHarness(200)

        response.emit('finish')
        response.emit('finish')

        assert.equal(events.length, 1)
    })

    void it('should not expose sensitive request data', () => {
        const { response, events } = createHarness(200)

        response.emit('finish')

        assert.equal(events.length, 1)

        const serialized = JSON.stringify(events[0])

        assert.equal(serialized.includes('PRIVATE_TOKEN_123'), false)
        assert.equal(serialized.includes('captcha-secret'), false)
        assert.equal(serialized.includes('private@example.org'), false)
        assert.equal(serialized.includes('client-controlled-id'), false)
    })

    void it('should report audit storage failures', async () => {
        const { response, errorCodes, next } =
            createHarness(200, true)

        response.emit('finish')

        await waitForAsync()

        assert.deepEqual(errorCodes, ['audit_write_failed'])
        assert.equal(next.mock.callCount(), 1)
    })
})
