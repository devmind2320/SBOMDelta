// Thin wrapper over fetch. Every call funnels through request() so that error
// shape, JSON parsing, and abort handling are defined exactly once.

// The API must be on the dashboard's own origin: the session cookie is
// same-site only and the API sends no CORS headers. A base is useful only for
// a path prefix, never for another host.
const BASE = import.meta.env.VITE_API_BASE ?? ''

// Must match auth.CSRFHeader on the server. Every state-changing request
// carries it; a cross-site form or script cannot.
export const CSRF_HEADER = 'X-SBOMDelta-Request'

let onUnauthenticated = () => {}

/**
 * Registers what to do when a request finds no usable session. The handler
 * gets 'signed_out' (401: missing or expired) or 'not_allowed' (403 on a read:
 * the account was removed from the allowlist).
 */
export function setUnauthenticatedHandler(handler) {
  onUnauthenticated = handler
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// notify: false leaves a 401 or 403 to the caller instead of the handler; the
// session check itself uses it, since its answer is what decides the route.
async function request(path, { signal, method = 'GET', notify = true } = {}) {
  const headers = { Accept: 'application/json' }
  if (method !== 'GET') headers[CSRF_HEADER] = '1'
  let response
  try {
    response = await fetch(`${BASE}${path}`, {
      signal,
      method,
      headers,
      credentials: 'same-origin',
    })
  } catch (cause) {
    // An aborted request is a normal consequence of navigating away; let the
    // caller distinguish it from a real network failure.
    if (cause.name === 'AbortError') throw cause
    throw new ApiError('Could not reach the API. Is the server running?', 0)
  }

  if (!response.ok) {
    // The API returns {"error": "..."} on failure, but a proxy or a crash can
    // produce something else entirely, so never assume the body parses.
    let detail = `Request failed with status ${response.status}`
    try {
      const body = await response.json()
      if (body?.error) detail = body.error
    } catch {
      /* keep the status-based message */
    }
    // A 403 on a state-changing request is the CSRF check, not the session.
    if (notify && response.status === 401) onUnauthenticated('signed_out')
    if (notify && response.status === 403 && method === 'GET') onUnauthenticated('not_allowed')
    throw new ApiError(detail, response.status)
  }

  if (response.status === 204) return null
  return response.json()
}

export const api = {
  /** The signed-in user, or an ApiError: 401 signed out, 403 not allowed. */
  me: (options) => request('/api/me', { ...options, notify: false }),

  /** Like me(), but a missing session is handled like any other request's. */
  checkSession: (options) => request('/api/me', options),

  logout: () => request('/api/auth/logout', { method: 'POST', notify: false }),

  /**
   * One page of the repositories GitHub reported for the signed-in user at
   * sign-in, with { repositories, total, page, perPage, listing }.
   */
  listMyRepositories: ({ page = 1, perPage = 30, q = '', untrackedOnly = false, ...options } = {}) =>
    request(
      `/api/me/repositories?page=${page}&perPage=${perPage}&q=${encodeURIComponent(q)}` +
        (untrackedOnly ? '&exclude=tracked' : ''),
      options,
    ),

  /** The repositories the signed-in user tracks, with their latest scans. */
  listTracked: (options) => request('/api/me/tracked', options).then((body) => body.repositories ?? []),

  /** Scans a repository's default branch head: { scan, outcome }. */
  requestScan: (repositoryId) => request(`/api/repos/${repositoryId}/scans`, { method: 'POST' }),

  /** Adds a repository to the signed-in user's tracked list without scanning it. */
  track: (repositoryId) => request(`/api/me/tracked/${repositoryId}`, { method: 'PUT' }),

  untrack: (repositoryId) => request(`/api/me/tracked/${repositoryId}`, { method: 'DELETE' }),

  /** The newest scans of the user's tracked repositories ("Last scans"). */
  listRecentScans: ({ limit = 20, repositoryId = null, ...options } = {}) =>
    request(
      `/api/me/scans?limit=${limit}` + (repositoryId ? `&repositoryId=${repositoryId}` : ''),
      options,
    ).then((body) => body.scans ?? []),

  /** A scan's risk score with its factors: { scored, assessment?, reason? }. */
  getRisk: (scanId, options) => request(`/api/scans/${scanId}/risk`, options),

  /** What a scan introduced and resolved against its base: { available, comparison?, reason? }. */
  getVulnerabilityChanges: (scanId, options) =>
    request(`/api/scans/${scanId}/vulnerability-changes`, options),

  /** Advisories across the user's tracked repositories: { vulnerabilities, coverage }. */
  impactVulnerabilities: (options) => request('/api/impact/vulnerabilities', options),

  /** A dependency across the user's tracked repositories: { components, coverage }. */
  impactComponents: (q, options) =>
    request(`/api/impact/components?q=${encodeURIComponent(q)}`, options),

  // access is 'active' (the API default), 'inactive' or 'all'. Inactive
  // repositories are ones SBOMDelta lost access to; their history is kept.
  listRepositories: ({ access = 'active', ...options } = {}) =>
    request(`/api/repos?access=${access}`, options).then((body) => body.repositories ?? []),

  getRepository: (id, options) => request(`/api/repos/${id}`, options),

  listScans: (id, { limit = 50, ...options } = {}) =>
    request(`/api/repos/${id}/scans?limit=${limit}`, options).then((body) => body.scans ?? []),

  getDriftTimeline: (id, { limit = 60, ...options } = {}) =>
    request(`/api/repos/${id}/drift?limit=${limit}`, options).then((body) => body.timeline ?? []),

  listPullRequests: (id, { limit = 50, ...options } = {}) =>
    request(`/api/repos/${id}/pulls?limit=${limit}`, options).then((body) => body.pullRequests ?? []),

  getPullRequest: (id, options) => request(`/api/pulls/${id}`, options),

  getScan: (id, options) => request(`/api/scans/${id}`, options),

  listComponents: (id, options) =>
    request(`/api/scans/${id}/components`, options).then((body) => body.components ?? []),

  listDriftEvents: (id, options) =>
    request(`/api/scans/${id}/drift`, options).then((body) => body.driftEvents ?? []),

  // Returns both the rows and whether enrichment has run at all, so the UI can
  // say "not analyzed yet" instead of the much stronger "no vulnerabilities".
  listVulnerabilities: (id, options) =>
    request(`/api/scans/${id}/vulnerabilities`, options).then((body) => ({
      vulnerabilities: body.vulnerabilities ?? [],
      enrichmentAvailable: body.enrichmentAvailable ?? false,
      summary: body.summary ?? null,
    })),

  sbomDownloadUrl: (id) => `${BASE}/api/scans/${id}/sbom`,
}
