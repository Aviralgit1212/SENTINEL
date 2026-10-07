import 'dotenv/config'

const port = Number(process.env.PORT ?? 5001)

if (!Number.isInteger(port) || port <= 0) {
  throw new Error('PORT must be a valid positive integer')
}

export const env = {
  port,
  mongodbUri:
    process.env.MONGODB_URI ??
    'mongodb://127.0.0.1:27017/sentinel',
  maxFileSizeMb: Number(process.env.MAX_FILE_SIZE_MB ?? 50),
}