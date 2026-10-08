import type { Request, Response } from 'express'

import { Scan } from '../models/Scan.js'

export async function getScanHistory(
  _req: Request,
  res: Response,
) {
  try {
    const scans = await Scan.find({
      userId: 'local-dev-user',
    })
      .sort({ createdAt: -1 })
      .lean()

    return res.json(scans)
  } catch (error) {
    console.error('Failed to load scan history:', error)

    return res.status(500).json({
      error: 'Failed to load scan history.',
    })
  }
}

export async function getScanById(
  req: Request,
  res: Response,
) {
  try {
    const scan = await Scan.findOne({
      scanId: req.params.scanId,
      userId: 'local-dev-user',
    }).lean()

    if (!scan) {
      return res.status(404).json({
        error: 'Scan not found.',
      })
    }

    return res.json(scan)
  } catch (error) {
    console.error('Failed to load scan:', error)

    return res.status(500).json({
      error: 'Failed to load scan.',
    })
  }
}