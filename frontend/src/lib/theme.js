import { useState } from 'react'

export function useTheme() {
  const [isDark, setDark] = useState(() => document.documentElement.classList.contains('dark'))
  const toggle = () => {
    const d = document.documentElement.classList.toggle('dark')
    localStorage.setItem('ss_theme', d ? 'dark' : 'light')
    setDark(d)
  }
  return [isDark, toggle]
}
