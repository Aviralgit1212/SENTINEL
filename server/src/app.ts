import express from 'express'
import cors from 'cors'

import apiRouter from './routes/api.js'
import type { IncomingMessage, ServerResponse } from 'node:http'

const app = express()

// Local-first: the server binds to loopback and only the Vite dev origin.
app.use(
  cors({
    origin: (origin, callback) => {
      const allowed = ['http://localhost:5173', 'http://127.0.0.1:5173']
      const extensionOrigin = process.env.SENTINEL_EXTENSION_ORIGIN
      if (!origin || allowed.includes(origin) || (extensionOrigin && origin === extensionOrigin)) return callback(null, true)
      return callback(new Error('Origin is not allowed by SENTINEL CORS policy.'))
    },
    allowedHeaders: ['Content-Type', 'X-Sentinel-Pairing-Token'],
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  }),
)

app.use(express.json({ limit: '1mb' }))

// Reject unexpected hosts (DNS-rebinding defense for a local API).
app.use((req: IncomingMessage & { headers: Record<string, string | string[] | undefined> }, res: ServerResponse, next: () => void) => {
  const host = (req.headers.host ?? '').split(':')[0]
  const allowed = ['localhost', '127.0.0.1']
  if (!allowed.includes(host)) {
    res.statusCode = 403
    res.end(JSON.stringify({ code: 403, message: 'Unexpected Host header.' }))
    return
  }
  next()
})

app.use('/api', apiRouter)

export default app
