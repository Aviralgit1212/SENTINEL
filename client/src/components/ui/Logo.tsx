/** A page with a scan line through it. Used everywhere the brand appears. */
export function Logo({ size = 22 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M6 3h8l4 4v14H6V3Z"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinejoin="round"
      />
      <path
        d="M3 13h18"
        stroke="var(--accent)"
        strokeWidth="1.75"
        strokeLinecap="round"
      />
    </svg>
  )
}

export function Wordmark() {
  return (
    <span className="wordmark">
      <Logo />
      Sentinel
    </span>
  )
}
