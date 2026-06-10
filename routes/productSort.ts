/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as models from '../models/index'

export function productSort () {
  return (req: Request, res: Response, next: NextFunction) => {
    const sortBy = String(req.query.sortBy ?? 'name')
    models.sequelize.query(`SELECT * FROM Products WHERE deletedAt IS NULL ORDER BY ${sortBy}`)
      .then(([products]: any) => {
        res.json({ status: 'success', data: products })
      }).catch((error: Error) => {
        next(error)
      })
  }
}
