import { Link, Navigate, useLocation } from 'react-router-dom'
import { SignIn, SignUp, useAuth } from '@clerk/clerk-react'

import { LoadingScreen } from '../../components/ui/LoadingScreen'
import { Wordmark } from '../../components/ui/Logo'
import './AuthPage.css'

const clerkAppearance = {
  variables: {
    colorPrimary: '#0b6b57',
    borderRadius: '8px',
    fontFamily: "'Schibsted Grotesk', system-ui, sans-serif",
  },
  elements: {
    card: { boxShadow: 'none', border: '1px solid #dcdfe3' },
  },
}

export default function AuthPage({ mode }: { mode: 'sign-in' | 'sign-up' }) {
  const { isLoaded, isSignedIn } = useAuth()
  const location = useLocation()

  if (!isLoaded) return <LoadingScreen />
  if (isSignedIn) return <Navigate to="/dashboard" replace />

  const from = location.state?.from
  const redirectUrl = typeof from === 'string' ? from : '/dashboard'

  return (
    <main className="auth-page">
      <Link to="/" aria-label="Sentinel home">
        <Wordmark />
      </Link>

      {mode === 'sign-in' ? (
        <SignIn
          routing="path"
          path="/sign-in"
          signUpUrl="/sign-up"
          forceRedirectUrl={redirectUrl}
          appearance={clerkAppearance}
        />
      ) : (
        <SignUp
          routing="path"
          path="/sign-up"
          signInUrl="/sign-in"
          forceRedirectUrl={redirectUrl}
          appearance={clerkAppearance}
        />
      )}
    </main>
  )
}
