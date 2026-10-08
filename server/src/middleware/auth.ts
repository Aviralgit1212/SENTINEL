import type { Request } from 'express'
import { getAuth } from '@clerk/express'

export function getAuthenticatedUserId(
  req: Request,
): string {
  const { userId } = getAuth(req)

  if (!userId) {
    throw new Error('Unauthorized')
  }

  return userId
}