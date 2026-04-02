// app/api/auth/callback/route.ts
import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify, importJWK } from 'jose'

const COOKIE_NAME = 'session_token'

export async function GET(req: NextRequest) {
  try {
    const url = new URL(req.url)
    const code = url.searchParams.get('code')

    if (!code) {
      return NextResponse.redirect(
        `${process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin}`.replace(/\/$/, '') + `/unauthorised`
      )
    }

    // ✅ Always use the canonical public URL for the redirect URI
    const baseUrl = (process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin).replace(/\/$/, '')
    const redirectUri = `${baseUrl}/api/auth/callback`
    console.log('TOKEN callback redirectUri:', redirectUri)

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: process.env.AZURE_CLIENT_ID!,
      scope: 'openid profile email',
    })

    if (process.env.AZURE_CLIENT_SECRET) {
      params.set('client_secret', process.env.AZURE_CLIENT_SECRET!)
    }

    const tokenRes = await fetch(
      `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
      }
    )

    const tokenData = await tokenRes.json()
    console.log('Azure token response:', tokenData)

    if (!tokenData.id_token) {
      console.error('No id_token returned', tokenData)
      return NextResponse.redirect(`${baseUrl}/unauthorised`)
    }

    const id_token = tokenData.id_token

    // --- Verify JWT ---
    const jwksRes = await fetch(process.env.AZURE_JWKS_URI!)
    const jwks = await jwksRes.json()
    const key = jwks.keys[0]
    const publicKey = await importJWK(key, 'RS256')
    const { payload } = await jwtVerify(id_token, publicKey, {
      issuer: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/v2.0`,
      audience: process.env.AZURE_CLIENT_ID,
    })

    console.log('Verified JWT payload:', payload)

    // --- Set Cookie ---
    const response = NextResponse.redirect(`${baseUrl}/`)
    response.cookies.set({
      name: COOKIE_NAME,
      value: id_token,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60 * 24,
    })

    return response
  } catch (err) {
    console.error('Auth callback error', err)
    return NextResponse.redirect(
      `${process.env.NEXT_PUBLIC_APP_URL || req.nextUrl.origin}`.replace(/\/$/, '') + `/unauthorised`
    )
  }
}