import { NextRequest, NextResponse } from 'next/server'
import { isAuthorisedUser, isExpiredToken } from '@/lib/auth'

const PUBLIC_PATHS = ['/unauthorised', '/health', '/api/auth']

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl

  // Allow public routes
  if (PUBLIC_PATHS.some((path) => pathname.startsWith(path))) {
    return NextResponse.next()
  }

  // Dev bypass
  if (process.env.DISABLE_AUTH === 'true') {
    return NextResponse.next()
  }

  const token = req.cookies.get('session_token')?.value

  // No token → redirect to login
  if (!token) {
    return redirectToLogin(req)
  }

  if (isExpiredToken(token)) {
    const res = redirectToLogin(req)
    res.cookies.delete('session_token')
    return res
  }

  if (!(await isAuthorisedUser(token))) {
    return redirectToUnauthorised(req)
  }
  return NextResponse.next()
}

function redirectToLogin(req: NextRequest) {
  const tenant = process.env.AZURE_TENANT_ID
  const clientId = process.env.AZURE_CLIENT_ID

  let baseUrl = process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin
  baseUrl = baseUrl.replace(/\/$/, '') // remove trailing slash if any

  const redirectUri = `${baseUrl}/api/auth/callback`
  console.log('middleware redirectUri:', redirectUri)

  const loginUrl =
    `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize` +
    `?client_id=${clientId}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=openid profile email` +
    `&response_mode=query`

  return NextResponse.redirect(loginUrl)
}

function redirectToUnauthorised(req: NextRequest) {
  const url = req.nextUrl.clone()
  url.pathname = '/unauthorised'
  return NextResponse.redirect(url)
}

// Configure which paths this middleware should run on
export const config = {
  matcher: [
    // Match all paths except those starting with excluded paths
    // You can customize this as needed
    '/((?!unauthorised|_next/static|_next/image|favicon.ico|api/health).*)',
  ],
}

