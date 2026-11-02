/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import { INVALID_LOG_PATH } from '../lib/logsAccessAudit'

// LA-06: marca el rechazo para que la auditoría lo registre como invalid_log_path.
function rejectLogPath (res: Response) {
  res.locals = res.locals ?? {}
  res.locals.auditReason = INVALID_LOG_PATH
  res.status(403)
}

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Solo se admiten nombres de archivo, no rutas.
    // Se rechazan separadores de Windows y Unix,
    // rutas con unidad y caracteres de control.
    const invalidName =
      typeof file !== 'string' ||
      file.length === 0 ||
      file === '.' ||
      file === '..' ||
      /[\\/:]/.test(file) ||
      /[\u0000-\u001f\u007f]/.test(file)

    if (invalidName) {
      rejectLogPath(res)
      next(new Error('Invalid log file name'))
      return
    }

    const logsDirectory = path.resolve('logs')
    const filePath = path.resolve(logsDirectory, file)
    const relativePath = path.relative(logsDirectory, filePath)

    // Defensa adicional: confirmar que la ruta
    // resuelta permanezca dentro del directorio logs.
    const escapesLogs =
      relativePath === '..' ||
      relativePath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativePath)

    if (escapesLogs) {
      rejectLogPath(res)
      next(new Error('Log file path is outside the allowed directory'))
      return
    }

    // El contenido de los logs proviene del cliente (URL, User-Agent, Referer):
    // se entrega como texto plano descargable para que nunca se interprete como HTML.
    res.sendFile(filePath, { headers: LOG_FILE_HEADERS })
  }
}

const LOG_FILE_HEADERS = {
  'Content-Type': 'text/plain; charset=utf-8',
  'Content-Disposition': 'attachment',
  'Content-Security-Policy': "default-src 'none'; sandbox",
  'X-Content-Type-Options': 'nosniff',
  'Cache-Control': 'no-store'
}

// Política para el listado HTML de /support/logs: sin scripts, sin recursos externos
// y en un origen aislado. Solo se permiten los estilos e íconos en línea de serve-index.
const LOG_LISTING_CSP = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'unsafe-inline'",
  'img-src data:',
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  'sandbox'
].join('; ')

export function secureLogViewerHeaders () {
  return (_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('Content-Security-Policy', LOG_LISTING_CSP)
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Cache-Control', 'no-store')
    next()
  }
}
