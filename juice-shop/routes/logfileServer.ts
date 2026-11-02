/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

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
      res.status(403)
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
      res.status(403)
      next(new Error('Log file path is outside the allowed directory'))
      return
    }

    res.sendFile(filePath)
  }
}
