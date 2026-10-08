import { Router } from 'express'

import multer from 'multer'

import path from 'node:path'

import fs from 'node:fs'

import { env } from '../config/env.js'

import { createScan } from '../controllers/scanController.js'

import {
  getScanHistory,
  getScanById,
} from '../controllers/historyController.js'

const router = Router()

const uploadDirectory = path.resolve(
  process.cwd(),
  'uploads',
)

fs.mkdirSync(uploadDirectory, {
  recursive: true,
})

const upload = multer({
  dest: uploadDirectory,

  limits: {
    fileSize:
      env.maxFileSizeMb * 1024 * 1024,
  },
})

// --------------------------------
// Create scan
// --------------------------------

router.post(
  '/',
  upload.single('file'),
  createScan,
)

// --------------------------------
// Scan history
// --------------------------------

router.get(
  '/',
  getScanHistory,
)

// --------------------------------
// Individual scan
// --------------------------------

router.get(
  '/:scanId',
  getScanById,
)

export default router