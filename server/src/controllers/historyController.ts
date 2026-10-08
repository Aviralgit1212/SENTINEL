import type {
  Request,
  Response,
} from 'express'

import { getAuthenticatedUserId } from '../middleware/auth.js'
import { Scan } from '../models/Scan.js'
import { getScanResult } from '../services/scanService.js'

export async function getScanHistory(
  req: Request,
  res: Response,
) {
  try {
    const userId =
      getAuthenticatedUserId(req)

    const scans =
      await Scan.find({
        userId,
      })
        .sort({
          createdAt: -1,
        })
        .lean()

    return res.json(scans)
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === 'Unauthorized'
    ) {
      return res.status(401).json({
        error:
          'Authentication required.',
      })
    }

    console.error(
      'Failed to load scan history:',
      error,
    )

    return res.status(500).json({
      error:
        'Failed to load scan history.',
    })
  }
}

export async function getScanById(
  req: Request,
  res: Response,
) {
  try {
    const userId =
      getAuthenticatedUserId(req)

    const scan =
      await Scan.findOne({
        scanId: req.params.scanId,
        userId,
      }).lean()

    if (!scan) {
      return res.status(404).json({
        error: 'Scan not found.',
      })
    }

    /*
     * The frontend polls this endpoint while
     * the expensive analysis is running.
     */
    if (
      scan.status ===
      'analyzing'
    ) {
      return res.json({
        scanId: scan.scanId,
        status: 'analyzing',
      })
    }

    if (
      scan.status ===
      'failed'
    ) {
      return res.json({
        scanId: scan.scanId,
        status: 'failed',
        error:
          scan.errorMessage ??
          'File analysis failed.',
      })
    }

    /*
     * Completed scans are returned in the
     * same structure as POST /api/scans.
     */
    const result =
      await getScanResult(
        userId,
        scan.scanId,
      )

    if (!result) {
      return res.status(404).json({
        error:
          'Scan result not found.',
      })
    }

    return res.json(result)
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === 'Unauthorized'
    ) {
      return res.status(401).json({
        error:
          'Authentication required.',
      })
    }

    console.error(
      'Failed to load scan:',
      error,
    )

    return res.status(500).json({
      error:
        'Failed to load scan.',
    })
  }
}