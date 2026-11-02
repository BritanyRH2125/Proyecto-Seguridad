
/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { EventEmitter } from 'node:events'
import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import type { Request, Response, NextFunction } from 'express'

import { auditLogsAccess, INVALID_LOG_PATH } from '../../lib/logsAccessAudit'
import { serveLogFiles } from '../../routes/logfileServer'
import {
    getAuditTraceId,
    type AuditEventInput
} from '../../lib/auditLogger'

function createHarness(
    statusCode: number,
    options: { authorization?: string, auditReason?: string } = {}
) {
    const req = {
        headers: options.authorization !== undefined
            ? { authorization: options.authorization }
            : {}
    } as unknown as Request

    const response = Object.assign(new EventEmitter(), {
        statusCode,
        locals: options.auditReason !== undefined
            ? { auditReason: options.auditReason }
            : {}
    })

    const events: AuditEventInput[] = []
    const writer = mock.fn(async (event: AuditEventInput) => {
        events.push(event)
    })
    const next = mock.fn()

    auditLogsAccess(writer, () => {})(
        req,
        response as unknown as Response,
        next as unknown as NextFunction
    )

    response.emit('finish')

    return { req, events, next }
}

void describe('logsAccessAudit - LA-06', () => {
    void it('debe registrar un acceso permitido como success/info', () => {
        const { req, events, next } = createHarness(200)

        assert.equal(next.mock.callCount(), 1)
        assert.equal(events.length, 1)
        assert.equal(events[0].event, 'logs.access')
        assert.equal(events[0].outcome, 'success')
        assert.equal(events[0].severity, 'info')
        assert.equal(events[0].traceId, getAuditTraceId(req))
    })

    void it('debe clasificar un acceso anónimo como unauthenticated', () => {
        const { events } = createHarness(401)

        assert.equal(events[0].outcome, 'denied')
        assert.equal(events[0].severity, 'warning')
        assert.deepEqual(events[0].details, {
            httpStatus: 401,
            reason: 'unauthenticated'
        })
    })

    void it('debe clasificar un token rechazado como invalid_token', () => {
        const { events } = createHarness(401, {
            authorization: 'Bearer token-no-valido'
        })

        assert.equal(events[0].outcome, 'denied')
        assert.equal(events[0].severity, 'error')
        assert.deepEqual(events[0].details, {
            httpStatus: 401,
            reason: 'invalid_token'
        })
    })

    void it('debe clasificar un usuario sin rol admin como intento de escalada', () => {
        const { events } = createHarness(403, {
            authorization: 'Bearer token-de-cliente'
        })

        assert.equal(events[0].outcome, 'denied')
        assert.equal(events[0].severity, 'critical')
        assert.deepEqual(events[0].details, {
            httpStatus: 403,
            reason: 'insufficient_privileges'
        })
    })

    void it('debe clasificar una ruta de log rechazada como invalid_log_path', () => {
        const { events } = createHarness(403, {
            authorization: 'Bearer token-de-admin',
            auditReason: 'invalid_log_path'
        })

        assert.equal(events[0].severity, 'critical')
        assert.deepEqual(events[0].details, {
            httpStatus: 403,
            reason: 'invalid_log_path'
        })
    })

    void it('no debe registrar el token ni el encabezado Authorization', () => {
        const { events } = createHarness(403, {
            authorization: 'Bearer PRIVATE_TOKEN_123'
        })

        assert.ok(!JSON.stringify(events[0]).includes('PRIVATE_TOKEN_123'))
    })

    void it('serveLogFiles debe marcar el rechazo de ruta para la auditoría', () => {
        const res = {
            locals: {},
            status() {
                return this
            },
            sendFile() {}
        } as unknown as Response

        serveLogFiles()(
            { params: { file: '..\\private-audit\\security-audit.log' } } as unknown as Request,
            res,
            () => {}
        )

        assert.equal(res.locals.auditReason, INVALID_LOG_PATH)
    })

    void it('no debe aceptar un motivo de auditoría arbitrario desde res.locals', () => {
        const { events } = createHarness(403, {
            authorization: 'Bearer token-de-cliente',
            auditReason: 'valor-no-permitido'
        })

        assert.deepEqual(events[0].details, {
            httpStatus: 403,
            reason: 'insufficient_privileges'
        })
    })
})
