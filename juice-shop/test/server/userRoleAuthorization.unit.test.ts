import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../../lib/insecurity'
import { requireAdminRole } from '../../lib/userRoleAuthorization'

test('GU-03: deniega acceso al usuario customer', () => {
  const getUser = mock.method(security.authenticatedUsers, 'from', () => ({
    data: { id: 1, role: 'customer' }
  } as any))

  try {
    let statusCode = 200
    let nextCalled = false

    const res = {
      status (code: number) {
        statusCode = code
        return this
      },
      send () {
        return this
      }
    } as unknown as Response

    requireAdminRole(
      {} as Request,
      res,
      (() => { nextCalled = true }) as NextFunction
    )

    assert.equal(statusCode, 403)
    assert.equal(nextCalled, false)
  } finally {
    getUser.mock.restore()
  }
})

test('GU-03: permite acceso al usuario admin', () => {
  const getUser = mock.method(security.authenticatedUsers, 'from', () => ({
    data: { id: 2, role: security.roles.admin }
  } as any))

  try {
    let nextCalled = false

    const res = {
      status () {
        throw new Error('El administrador no debe ser rechazado')
      }
    } as unknown as Response

    requireAdminRole(
      {} as Request,
      res,
      (() => { nextCalled = true }) as NextFunction
    )

    assert.equal(nextCalled, true)
  } finally {
    getUser.mock.restore()
  }
})
