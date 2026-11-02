
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

type AuditWriter = (event: AuditEventInput) => Promise<void>

export function auditDataExport(
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

            const outcome: AuditEventInput['outcome'] =
                httpStatus === 401 || httpStatus === 403
                    ? 'denied'
                    : httpStatus >= 400
                        ? 'failure'
                        : 'success'

            const severity: AuditEventInput['severity'] =
                httpStatus >= 500
                    ? 'error'
                    : httpStatus >= 400
                        ? 'warning'
                        : 'info'

            void tryWriteAuditEvent(
                writer,
                {
                    event: 'data.export',
                    outcome,
                    severity,
                    traceId: getAuditTraceId(req),
                    details: {
                        httpStatus
                    }
                },
                onFailure
            )
        })

        next()
    }
}
