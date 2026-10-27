/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import { downloadSafeProfileImage } from '../lib/safeProfileImageDownload'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      res.status(401).send('GU-05: autenticación requerida')
      return
    }

    if (typeof req.body?.imageUrl !== 'string' ||
        req.body.imageUrl.trim() === '') {
      res.status(400).send('GU-05: URL de imagen inválida')
      return
    }

    try {
      // GU-05: Prevención de SSRF en imágenes de perfil.
      // Validar destino, IP de conexión, redirecciones,
      // contenido y tamaño antes de guardar la imagen.
      const { buffer, extension } =
        await downloadSafeProfileImage(req.body.imageUrl)

      const filename = `${loggedInUser.data.id}.${extension}`
      const destination = path.resolve(
        'frontend/dist/frontend/assets/public/images/uploads',
        filename
      )

      await fs.writeFile(destination, buffer)

      const user = await UserModel.findByPk(loggedInUser.data.id)
      await user?.update({
        profileImage: `assets/public/images/uploads/${filename}`
      })

      res.location(process.env.BASE_PATH + '/profile')
      res.redirect(process.env.BASE_PATH + '/profile')
    } catch (error) {
      logger.warn(
        'GU-05: carga de imagen rechazada: ' +
        (error instanceof Error ? error.message : String(error))
      )

      // GU-05: Una URL rechazada no debe actualizar el perfil.
      res.status(400).send('GU-05: imagen o destino no permitido')
    }
  }
}
