import mongoose from 'mongoose'

import { Scan } from '../models/Scan.js'
import { env } from './env.js'

export async function connectToDatabase() {
  try {
    await mongoose.connect(
      env.mongodbUri,
    )

    /*
     * Ensure the idempotency index exists
     * before accepting API requests.
     */
    await Scan.createIndexes()

    console.log('MongoDB connected.')
    console.log('Scan indexes ready.')
  } catch (error) {
    console.error(
      'MongoDB connection failed:',
      error,
    )

    throw error
  }
}