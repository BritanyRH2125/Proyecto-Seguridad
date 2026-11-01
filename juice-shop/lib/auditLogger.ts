
/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { appendFile } from 'node:fs/promises'

export interface AuditEventInput {
    event: string
    outcome: 'success' | 'failure' | 'denied'
    severity: 'info' | 'warning' | 'error' | 'critical'
    traceId: string
    details?: Record<string, unknown>
}

const REDACTED = '[REDACTED]'

const sensitiveKeys = new Set([
    'password',
    'passwordrepeat',
    'authorization',
    'cookie',
    'setcookie',
    'token',
    'accesstoken',
    'refreshtoken',
    'apikey',
    'secret',
    'totpsecret',
    'cardnumber',
    'creditcard',
    'sessionid'
])

function sanitizeText(value: string, maxLength: number): string {
    return value
        .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ')
        .slice(0, maxLength)
}

function sanitizeDetailValue(
    value: unknown,
    key: string,
    depth = 0
): unknown {
    const normalizedKey = key.replace(/[\s_-]/g, '').toLowerCase()

    if (sensitiveKeys.has(normalizedKey)) {
        return REDACTED
    }

    if (typeof value === 'string') {
        return sanitizeText(value, 500)
    }

    if (value === null || typeof value === 'boolean') {
        return value
    }

    if (typeof value === 'number') {
        return Number.isFinite(value) ? value : null
    }

    if (depth >= 3) {
        return '[TRUNCATED]'
    }

    if (Array.isArray(value)) {
        return value.slice(0, 20).map(item =>
            sanitizeDetailValue(item, '', depth + 1)
        )
    }

    if (typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value as Record<string, unknown>)
                .slice(0, 20)
                .map(([nestedKey, nestedValue]) => [
                    sanitizeText(nestedKey, 80),
                    sanitizeDetailValue(nestedValue, nestedKey, depth + 1)
                ])
        )
    }

    return '[UNSUPPORTED]'
}

export function serializeAuditEvent(input: AuditEventInput): string {
    const record = {
        timestamp: new Date().toISOString(),
        event: sanitizeText(input.event, 120),
        outcome: input.outcome,
        severity: input.severity,
        traceId: sanitizeText(input.traceId, 128),
        ...(input.details !== undefined && {
            details: sanitizeDetailValue(input.details, '')
        })
    }

    return JSON.stringify(record) + '\n'
}

export function createAuditWriter(filePath: string) {
    return async (input: AuditEventInput): Promise<void> => {
        const line = serializeAuditEvent(input)

        await appendFile(filePath, line, {
            encoding: 'utf8',
            flag: 'a',
            mode: 0o600
        })
    }
}