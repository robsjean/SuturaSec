import { scansApi } from '../services/api'
import { apiError } from './scan'
import { toast } from './toast'

/**
 * Ouvre le rapport d'une analyse. L'onglet est ouvert tout de suite (dans le geste
 * utilisateur, sinon il serait bloqué comme popup), puis redirigé vers un lien à portée
 * limitée (10 min, ce scan uniquement) : le token de session ne quitte jamais la page.
 */
export async function openReport(scanId) {
  const win = window.open('', '_blank')
  try {
    const { data } = await scansApi.reportLink(scanId)
    if (win) win.location.href = data.url
    else window.location.href = data.url
  } catch (err) {
    if (win) win.close()
    toast(apiError(err, "Impossible d'ouvrir le rapport."), 'error')
  }
}
