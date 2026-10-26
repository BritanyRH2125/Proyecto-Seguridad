import { type Request, type Response, type NextFunction } from 'express'
import * as security from './insecurity'

export function requireAdminRole (
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const authenticatedUser = security.authenticatedUsers.from(req)

  if (!authenticatedUser) {
    res.status(401).send('Unauthorized')
    return
  }

  if (authenticatedUser.data.role !== security.roles.admin) {
    res.status(403).send('Forbidden: insufficient permissions')
    return
  }

  next()
}
