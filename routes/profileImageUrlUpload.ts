/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT 
 */

import fs from 'node:fs'
import path from 'node:path'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import { promises as dnsPromises } from 'node:dns'
import net from 'node:net'
import { URL } from 'node:url'

import * as security from '../lib/insecurity'
import rateLimit from 'express-rate-limit'
import { UserModel } from '../models/user'
export const profileImageUrlUploadLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 50
})

import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts[0] === 10) return true
  if (parts[0] === 127) return true
          const safeId = path.basename(String(loggedInUser.data.id)).replace(/(\.\.(\/|\\))/g, '')
          const uploadsDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
          const safeFilePath = path.resolve(uploadsDir, `${safeId}.${ext}`)
          if (!safeFilePath.startsWith(uploadsDir + path.sep)) {
            throw new Error('Invalid file path')
          }
          const fileStream = fs.createWriteStream(safeFilePath, { flags: 'w' })
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
  if (parts[0] === 192 && parts[1] === 168) return true
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true
  if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true
  return false
}

function isPrivateIPv6 (ip: string): boolean {
  const lower = ip.toLowerCase()
  if (lower === '::1' || lower === '::') return true
  if (/^fe[89ab][0-9a-f]/.test(lower)) return true
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true
  if (lower.startsWith('ff')) return true
  return false
}

function isPrivateIP (ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip)
  if (net.isIPv6(ip)) return isPrivateIPv6(ip)
  return false
}

const ALLOWED_HOSTS = new Set<string>([
  'placecats.com',
  'placebear.com',
  'picsum.photos',
  'loremflickr.com',
  'via.placeholder.com',
  'upload.wikimedia.org',
  'raw.githubusercontent.com'
])

async function validateUrl (urlString: string): Promise<boolean> {
  try {
    const parsed = new URL(urlString)
    if (!['http:', 'https:'].includes(parsed.protocol)) return false
    if (!ALLOWED_HOSTS.has(parsed.hostname.toLowerCase())) return false
    const addresses = await dnsPromises.lookup(parsed.hostname, { all: true })
    if (addresses.some(addr => isPrivateIP(addr.address))) return false
    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const isValid = await validateUrl(url)
          if (!isValid) {
            throw new Error('Invalid URL or access to private IP addresses is not allowed.')
          }
          const parsedSafeUrl = new URL(url)
          const safeHost = parsedSafeUrl.hostname.toLowerCase()
          const matchedHost = [...ALLOWED_HOSTS].find(h => h === safeHost)
          if (!matchedHost) {
            throw new Error('Host is not in the allowlist.')
          }
          const pathMatch = /^[A-Za-z0-9/_.\-]*$/.exec(parsedSafeUrl.pathname)
          if (!pathMatch) {
            throw new Error('Invalid path characters.')
          }
          const safePath = pathMatch[0]
          const fetchUrl = `https://${matchedHost}${safePath}`
          const response = await fetch(fetchUrl)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
