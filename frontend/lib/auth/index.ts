import { decodeJwt, JWTPayload } from 'jose'

export type AuthUser = {
  email: string
}

export function getUserFromToken(token: string): AuthUser | null {
  try {
    const decoded = decodeJwt(token) as JWTPayload

    const email =
      (decoded.email as string) ||
      (decoded.preferred_username as string)

    if (!email) {
      console.error('No email in token')
      return null
    }

    return { email }
  } catch (err) {
    console.error('Failed to decode JWT', err)
    return null
  }
}

export function isAuthorisedUser(token: string): boolean {
  const user = getUserFromToken(token)

  if (!user) return false

  // 🔥 Minimal rule: must have email
  return true
}