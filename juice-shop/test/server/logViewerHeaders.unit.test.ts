
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import type { Request, Response } from 'express'
import {
    serveLogFiles,
    secureLogViewerHeaders
} from '../../routes/logfileServer'

function executeLogFileRequest(file: string) {
    let sendFileOptions: { headers?: Record<string, string> } | undefined

    const req = {
        params: { file }
    } as unknown as Request

    const res = {
        sendFile(_filePath: string, options?: { headers?: Record<string, string> }) {
            sendFileOptions = options
        },
        status() {
            return this
        }
    } as unknown as Response

    serveLogFiles()(req, res, () => {})

    return sendFileOptions?.headers ?? {}
}

function executeLogListingRequest() {
    const headers = new Map<string, string>()
    let nextCalled = false

    const res = {
        setHeader(name: string, value: string) {
            headers.set(name.toLowerCase(), value)
            return this
        }
    } as unknown as Response

    secureLogViewerHeaders()({} as Request, res, () => {
        nextCalled = true
    })

    return { headers, nextCalled }
}

void describe('LA-05: visualización segura de bitácoras', () => {
    void it('debe entregar los archivos de log como texto plano', () => {
        const headers = executeLogFileRequest('access.log')

        assert.equal(headers['Content-Type'], 'text/plain; charset=utf-8')
    })

    void it('debe forzar la descarga de los archivos de log', () => {
        const headers = executeLogFileRequest('access.log')

        assert.equal(headers['Content-Disposition'], 'attachment')
    })

    void it('debe aplicar una CSP restrictiva a los archivos de log', () => {
        const csp = executeLogFileRequest('access.log')['Content-Security-Policy'] ?? ''

        assert.match(csp, /default-src 'none'/)
        assert.match(csp, /sandbox/)
    })

    void it('debe aplicar una CSP restrictiva al listado de logs', () => {
        const { headers, nextCalled } = executeLogListingRequest()
        const csp = headers.get('content-security-policy') ?? ''

        assert.match(csp, /default-src 'none'/)
        assert.match(csp, /script-src 'none'/)
        assert.match(csp, /sandbox/)
        assert.equal(nextCalled, true)
    })

    void it('debe impedir el rastreo de tipo MIME y el almacenamiento en caché', () => {
        const { headers } = executeLogListingRequest()

        assert.equal(headers.get('x-content-type-options'), 'nosniff')
        assert.equal(headers.get('cache-control'), 'no-store')
    })
})
