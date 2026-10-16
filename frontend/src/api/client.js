// Thin wrapper over fetch. Every call funnels through request() so that error
// shape, JSON parsing, and abort handling are defined exactly once.

const BASE = import.meta.env.VITE_API_BASE ?? ''

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request(path, { signal } = {}) {
  let response
  try {
    response = await fetch(`${BASE}${path}`, {
      signal,
      headers: { Accept: 'application/json' },
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
    throw new ApiError(detail, response.status)
  }

  return response.json()
}

export const api = {
  listRepositories: (options) =>
    request('/api/repos', options).then((body) => body.repositories ?? []),

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
    })),

  sbomDownloadUrl: (id) => `${BASE}/api/scans/${id}/sbom`,
}
