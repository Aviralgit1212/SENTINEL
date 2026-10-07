import express from 'express'
import cors from 'cors'

import scanRoutes from './routes/scanRoutes.js'

const app = express()

app.use(
  cors({
    origin: [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
    ],
  }),
)

app.use(express.json())

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'sentinel-server',
  })
})

app.use('/api/scans', scanRoutes)

export default app