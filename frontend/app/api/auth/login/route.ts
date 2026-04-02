// app/api/auth/login/route.ts
import { NextRequest, NextResponse } from 'next/server'

export async function GET(req: NextRequest) {
  const baseUrl = (process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin).replace(/\/$/, '')
  const redirectUri = `${baseUrl}/api/auth/callback`
  console.log(console.log('LOGIN redirectUri:', redirectUri))

  const params = new URLSearchParams({
    client_id: process.env.AZURE_CLIENT_ID!,
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: 'openid profile email',
    state: 'some-random-state', // optional, for CSRF protection
  })

  const loginUrl = `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/authorize?${params.toString()}`
  return NextResponse.redirect(loginUrl)
}