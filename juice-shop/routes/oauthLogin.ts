/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import crypto from 'node:crypto'

import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// FIX PR.AA-02: login con Google validado en el servidor.
// El backend verifica el access_token contra Google y autentica por el email que Google confirma,
// sin depender de ninguna contraseña derivada del email (que sería pública y predecible).
export function oauthLogin () {
  return (req: Request, res: Response, next: NextFunction) => {
    const accessToken = req.body?.access_token
    if (!accessToken) {
      res.status(401).json({ error: 'OAuth access token required' })
      return
    }
    // 1) Validar el token contra Google desde el servidor (no desde el navegador)
    fetch('https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=' + encodeURIComponent(accessToken))
      .then(async (response) => {
        if (!response.ok) {
          res.status(401).json({ error: 'Invalid Google OAuth token' })
          return
        }
        const profile: any = await response.json()
        const email: string = profile?.email
        if (!email) {
          res.status(401).json({ error: 'Google profile without email' })
          return
        }
        // 2) Buscar (o crear) la cuenta por el email verificado por Google.
        //    La contraseña es aleatoria y nunca se usa para autenticar a un usuario OAuth.
        let user = await UserModel.findOne({ where: { email, deletedAt: null } })
        if (!user) {
          user = await UserModel.create({ email, password: crypto.randomBytes(32).toString('hex'), role: security.roles.customer })
        }
        // 3) Emitir el JWT reutilizando la misma lógica del login normal
        const userData = utils.queryResultToJson(user).data
        const [basket] = await BasketModel.findOrCreate({ where: { UserId: userData.id } })
        const authenticatedUser = { data: userData, bid: basket.id }
        const token = security.authorize(authenticatedUser)
        security.authenticatedUsers.put(token, authenticatedUser)
        res.json({ authentication: { token, bid: basket.id, umail: userData.email } })
      })
      .catch((error: Error) => { next(error) })
  }
}
