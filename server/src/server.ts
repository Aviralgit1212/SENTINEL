import app from './app.js'

// Optional positional argument wins (start-server.sh), then SENTINEL_PORT,
// then PORT when it looks valid, then the default.
const cliPort = Number(process.argv[2])
const envPort = Number(
  process.env.SENTINEL_PORT && process.env.SENTINEL_PORT !== ''
    ? process.env.SENTINEL_PORT
    : (process.env.PORT && Number(process.env.PORT) > 0 ? process.env.PORT : ''),
)
const port = Number(
  Number.isInteger(cliPort) && cliPort > 0 ? cliPort : envPort > 0 ? envPort : 5001,
)
if (!Number.isInteger(port) || port <= 0) {
  throw new Error('PORT must be a positive integer')
}

// Loopback-only by default: a local security API must not be reachable
// from other machines on the network.
const host = process.env.HOST ?? '127.0.0.1'

app.listen(port, host, () => {
  console.log(`[sentinel] API listening on http://${host}:${port}`)
})
