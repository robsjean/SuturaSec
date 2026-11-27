import { useEffect, useState } from 'react'

/** Affiche une notification : toast('Message') ou toast('Erreur', 'error'). */
export const toast = (message, type = 'success') =>
  window.dispatchEvent(new CustomEvent('ss-toast', { detail: { message, type } }))

export function useToast() {
  const [current, setCurrent] = useState(null)
  useEffect(() => {
    let timer
    const onToast = (e) => {
      setCurrent({ message: e.detail?.message || '', type: e.detail?.type || 'success' })
      clearTimeout(timer)
      timer = setTimeout(() => setCurrent(null), 6000)
    }
    window.addEventListener('ss-toast', onToast)
    return () => { window.removeEventListener('ss-toast', onToast); clearTimeout(timer) }
  }, [])
  return [current, () => setCurrent(null)]
}
