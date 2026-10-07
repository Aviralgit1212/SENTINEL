import { Navigate, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '@clerk/clerk-react'

import AppHeader from './components/layout/AppHeader'
import { LoadingScreen } from './components/ui/LoadingScreen'
import AuthPage from './pages/auth/AuthPage'
import DashboardPage from './pages/dashboard/DashboardPage'
import LandingPage from './pages/landing/LandingPage'
import ScanPage from './pages/scan/ScanPage'
import SettingsPage from './pages/settings/SettingsPage'

/** Everything inside this layout requires a signed-in user. */
function AppLayout() {
  const { isLoaded, isSignedIn } = useAuth()
  const location = useLocation()

  if (!isLoaded) return <LoadingScreen />

  if (!isSignedIn) {
    return <Navigate to="/sign-in" replace state={{ from: location.pathname }} />
  }

  return (
    <>
      <AppHeader />
      <Outlet />
    </>
  )
}

function LandingRoute() {
  const navigate = useNavigate()
  const { isLoaded, isSignedIn } = useAuth()

  if (!isLoaded) return <LoadingScreen />

  const signedIn = Boolean(isSignedIn)

  return (
    <LandingPage
      isSignedIn={signedIn}
      onSignIn={() => navigate('/sign-in')}
      onStart={() => navigate(signedIn ? '/dashboard' : '/sign-in')}
    />
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingRoute />} />
      <Route path="/sign-in/*" element={<AuthPage mode="sign-in" />} />
      <Route path="/sign-up/*" element={<AuthPage mode="sign-up" />} />

      <Route element={<AppLayout />}>
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
