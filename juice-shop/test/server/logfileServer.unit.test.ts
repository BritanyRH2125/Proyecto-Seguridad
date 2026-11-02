
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import type { Request, Response } from 'express'
import { serveLogFiles } from '../../routes/logfileServer'

function executeLogRequest(file: string) {
    let sentFile: string | undefined
    let statusCode: number | undefined
    let nextError: unknown

    const req = {
        params: { file }
    } as unknown as Request

    const res = {
        sendFile(filePath: string) {
            sentFile = filePath
        },
        status(code: number) {
            statusCode = code
            return this
        }
    } as unknown as Response

    serveLogFiles()(req, res, (error?: unknown) => {
        nextError = error
    })

    return { sentFile, statusCode, nextError }
}


void describe('LA-03: validación segura de archivos de logs', () => {
    void it('debe permitir un nombre de archivo válido', () => {
        const result = executeLogRequest('access.log')

        assert.equal(
            result.sentFile,
            path.resolve('logs', 'access.log')
        )
        assert.equal(result.nextError, undefined)
    })

    void it('debe rechazar rutas con barras normales', () => {
        const result = executeLogRequest(
            '../private-audit/security-audit.log'
        )

        assert.equal(result.sentFile, undefined)
        assert.equal(result.statusCode, 403)
        assert.ok(result.nextError instanceof Error)
    })

    void it('debe rechazar recorrido con barras invertidas', () => {
        const result = executeLogRequest(
            '..\\private-audit\\security-audit.log'
        )

        assert.equal(result.sentFile, undefined)
        assert.equal(result.statusCode, 403)
        assert.ok(result.nextError instanceof Error)
    })

    void it('debe rechazar el componente de directorio superior', () => {
        const result = executeLogRequest('..')

        assert.equal(result.sentFile, undefined)
        assert.equal(result.statusCode, 403)
        assert.ok(result.nextError instanceof Error)
    })

    void it('debe rechazar rutas absolutas de Windows', () => {
        const result = executeLogRequest('C:\\Windows\\win.ini')

        assert.equal(result.sentFile, undefined)
        assert.equal(result.statusCode, 403)
        assert.ok(result.nextError instanceof Error)
    })

    void it('debe rechazar nombres con dos puntos', () => {
        const result = executeLogRequest('access.log:contenido')

        assert.equal(result.sentFile, undefined)
        assert.equal(result.statusCode, 403)
        assert.ok(result.nextError instanceof Error)
    })
})
