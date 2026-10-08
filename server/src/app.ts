import express from 'express'
import cors from 'cors'
import { clerkMiddleware } from '@clerk/express'

import scanRoutes from './routes/scanRoutes.js'

const app = express()

app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
    ],

    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Scan-Request-Id',
    ],

    methods: [
      'GET',
      'POST',
      'PUT',
      'PATCH',
      'DELETE',
      'OPTIONS',
    ],
  }),
)

app.use(express.json())

app.use(clerkMiddleware())

app.get(
  '/api/health',
  (_req, res) => {
    res.json({
      ok: true,
      service: 'sentinel-server',
    })
  },
)

app.use(
  '/api/scans',
  scanRoutes,
)

export default app