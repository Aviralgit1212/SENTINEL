import type { Request, Response } from 'express'

import { analyzeFile } from '../services/scanService.js'

export async function createScan(
  req: Request,
  res: Response,
) {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: 'No file was uploaded.',
      })
    }

    const result = await analyzeFile(req.file)

    return res.status(201).json(result)
  } catch (error) {
    console.error('Scan failed:', error)

    return res.status(500).json({
      error: 'File analysis failed.',
    })
  }
}