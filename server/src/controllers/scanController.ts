import type {
  Request,
  Response,
} from 'express'

import fs from 'node:fs/promises'

import { getAuthenticatedUserId } from '../middleware/auth.js'
import { analyzeFile } from '../services/scanService.js'

const SCAN_REQUEST_ID_HEADER =
  'x-scan-request-id'

function readScanRequestId(
  req: Request,
): string | null {
  const value =
    req
      .header(SCAN_REQUEST_ID_HEADER)
      ?.trim()

  if (!value) {
    return null
  }

  /*
   * The frontend generates IDs using
   * crypto.randomUUID().
   *
   * Validate the format before storing it.
   */
  const uuidPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

  return uuidPattern.test(value)
    ? value
    : null
}

export async function createScan(
  req: Request,
  res: Response,
) {
  try {
    if (!req.file) {
      return res.status(400).json({
        error:
          'No file was uploaded.',
      })
    }

    const userId =
      getAuthenticatedUserId(req)

    const scanRequestId =
      readScanRequestId(req)

    if (!scanRequestId) {
      return res.status(400).json({
        error:
          'Missing or invalid scan request ID.',
      })
    }

    const result =
      await analyzeFile(
        req.file,
        userId,
        scanRequestId,
      )

    /*
     * First request completed the analysis.
     */
    if (result.status === 'completed') {
      return res
        .status(201)
        .json(result.result)
    }

    /*
     * Another request already owns the
     * same scan and is still processing.
     */
    if (result.status === 'analyzing') {
      return res.status(202).json({
        scanId: result.scanId,
        status: 'analyzing',
      })
    }

    /*
     * Existing scan already failed.
     */
    return res.status(500).json({
      scanId: result.scanId,
      status: 'failed',
      error: result.error,
    })
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
      'Scan failed:',
      error,
    )

    return res.status(500).json({
      error:
        'File analysis failed.',
    })
  } finally {
    /*
     * Every uploaded temporary file is
     * deleted after the request finishes.
     */
    if (req.file?.path) {
      try {
        await fs.unlink(
          req.file.path,
        )
      } catch (cleanupError) {
        console.error(
          'Failed to delete temporary upload:',
          cleanupError,
        )
      }
    }
  }
}