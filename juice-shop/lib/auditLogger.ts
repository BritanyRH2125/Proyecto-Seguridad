
/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

export interface AuditEventInput {
    event: string
    outcome: 'success' | 'failure' | 'denied'
    severity: 'info' | 'warning' | 'error' | 'critical'
    traceId: string
}

export function serializeAuditEvent(input: AuditEventInput): string {
    const record = {
        timestamp: new Date().toISOString(),
        event: input.event,
        outcome: input.outcome,
        severity: input.severity,
        traceId: input.traceId
    }

    return JSON.stringify(record) + '\n'
}
