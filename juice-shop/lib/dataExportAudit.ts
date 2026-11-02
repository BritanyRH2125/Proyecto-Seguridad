
/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import type { Request, Response, NextFunction } from 'express'
import type { AuditEventInput } from './auditLogger'

type AuditWriter = (event: AuditEventInput) => Promise<void>

// Implementación provisional para comenzar las pruebas RED.
// Todavía no registra eventos.
export function auditDataExport(
    _writer: AuditWriter,
    _onFailure: (code: string) => void
) {
    return (
        _req: Request,
        _res: Response,
        next: NextFunction
    ): void => {
        next()
    }
}
