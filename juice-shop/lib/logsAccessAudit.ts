
/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import type { Request, Response, NextFunction } from 'express'
import {
    getAuditTraceId,
    tryWriteAuditEvent,
    type AuditEventInput
} from './auditLogger'
import { jwtFrom } from './utils'

type AuditWriter = (event: AuditEventInput) => Promise<void>

// Motivo que routes/logfileServer.ts deja en res.locals al rechazar una ruta (LA-03).
export const INVALID_LOG_PATH = 'invalid_log_path'

interface DenialClassification {
    reason: string
    severity: AuditEventInput['severity']
}

// Distingue el tipo de rechazo para que un intento de escalada de privilegios
// o un token no confiable no quede registrado igual que un acceso anónimo.
function classifyDenial(
    req: Request,
    res: Response,
    httpStatus: number
): DenialClassification | undefined {
    if (httpStatus === 401) {
        return jwtFrom(req)
            ? { reason: 'invalid_token', severity: 'error' }
            : { reason: 'unauthenticated', severity: 'warning' }
    }

    if (httpStatus === 403) {
        // Solo se acepta el motivo conocido; cualquier otro valor se ignora.
        return res.locals?.auditReason === INVALID_LOG_PATH
            ? { reason: INVALID_LOG_PATH, severity: 'critical' }
            : { reason: 'insufficient_privileges', severity: 'critical' }
    }

    return undefined
}

// Middleware de auditoría de /support/logs extraído de server.ts (LA-01).
export function auditLogsAccess(
    writer: AuditWriter,
    onFailure: (code: string) => void
) {
    return (
        req: Request,
        res: Response,
        next: NextFunction
    ): void => {
        res.once('finish', () => {
            const httpStatus = res.statusCode
            const denial = classifyDenial(req, res, httpStatus)

            const outcome: AuditEventInput['outcome'] =
                denial !== undefined
                    ? 'denied'
                    : httpStatus >= 400
                        ? 'failure'
                        : 'success'

            const severity: AuditEventInput['severity'] =
                denial !== undefined
                    ? denial.severity
                    : httpStatus >= 500
                        ? 'error'
                        : httpStatus >= 400
                            ? 'warning'
                            : 'info'

            void tryWriteAuditEvent(
                writer,
                {
                    event: 'logs.access',
                    outcome,
                    severity,
                    traceId: getAuditTraceId(req),
                    details: {
                        httpStatus,
                        ...(denial !== undefined && { reason: denial.reason })
                    }
                },
                onFailure
            )
        })

        next()
    }
}
