import app from './app.js'
import { env } from './config/env.js'
import { connectToDatabase } from './config/database.js'

async function startServer() {
  try {
    await connectToDatabase()

    app.listen(env.port, () => {
      console.log(
        `SENTINEL server running on http://localhost:${env.port}`,
      )
    })
  } catch (error) {
    console.error('Failed to start SENTINEL server:', error)

    process.exit(1)
  }
}

startServer()