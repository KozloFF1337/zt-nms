import axios, { AxiosError, AxiosRequestConfig } from 'axios'
import { useAuthStore } from '@/stores/auth'
import type { ErrorResponse } from '@/types/api'

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor - add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor - handle errors
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError<ErrorResponse>) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout()
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Generic API request helper
export async function apiRequest<T>(
  config: AxiosRequestConfig
): Promise<T> {
  const response = await apiClient.request<T>(config)
  return response.data
}

// Auth API
export const authApi = {
  getChallenge: () =>
    apiRequest<{ challenge: string; expires_at: string }>({
      method: 'POST',
      url: '/auth/challenge',
    }),

  authenticate: (data: { public_key: string; challenge: string; signature: string }) =>
    apiRequest<{
      access_token: string
      token_type: string
      expires_in: number
      identity: import('@/types/api').Identity
    }>({
      method: 'POST',
      url: '/auth/authenticate',
      data,
    }),

  login: (data: { username: string; password: string }) =>
    apiRequest<{
      access_token: string
      token_type: string
      expires_in: number
      identity: import('@/types/api').Identity
    }>({
      method: 'POST',
      url: '/auth/login',
      data,
    }),

  refreshToken: (refresh_token: string) =>
    apiRequest<{ access_token: string; expires_in: number }>({
      method: 'POST',
      url: '/auth/token/refresh',
      data: { refresh_token },
    }),
}

// Identities API
export const identitiesApi = {
  list: (params?: { type?: string; status?: string; search?: string; limit?: number; offset?: number }) =>
    apiRequest<{ identities: import('@/types/api').Identity[]; total: number; limit: number; offset: number }>({
      method: 'GET',
      url: '/identities',
      params,
    }),

  get: (id: string) =>
    apiRequest<import('@/types/api').Identity>({
      method: 'GET',
      url: `/identities/${id}`,
    }),

  create: (data: { type: string; attributes: Record<string, unknown>; public_key: string }) =>
    apiRequest<import('@/types/api').Identity>({
      method: 'POST',
      url: '/identities',
      data,
    }),

  update: (id: string, data: Partial<import('@/types/api').Identity>) =>
    apiRequest<import('@/types/api').Identity>({
      method: 'PUT',
      url: `/identities/${id}`,
      data,
    }),

  delete: (id: string) =>
    apiRequest<void>({
      method: 'DELETE',
      url: `/identities/${id}`,
    }),

  suspend: (id: string, reason: string) =>
    apiRequest<{ status: string }>({
      method: 'POST',
      url: `/identities/${id}/suspend`,
      data: { reason },
    }),

  activate: (id: string) =>
    apiRequest<{ status: string }>({
      method: 'POST',
      url: `/identities/${id}/activate`,
    }),
}

// Devices API
export const devicesApi = {
  list: (params?: { role?: string; location?: string; status?: string; limit?: number; offset?: number }) =>
    apiRequest<{ devices: import('@/types/api').Device[]; total: number }>({
      method: 'GET',
      url: '/devices',
      params,
    }),

  get: (id: string) =>
    apiRequest<import('@/types/api').Device>({
      method: 'GET',
      url: `/devices/${id}`,
    }),

  register: (data: Partial<import('@/types/api').Device>) =>
    apiRequest<import('@/types/api').Device>({
      method: 'POST',
      url: '/devices',
      data,
    }),

  update: (id: string, data: Partial<import('@/types/api').Device>) =>
    apiRequest<import('@/types/api').Device>({
      method: 'PUT',
      url: `/devices/${id}`,
      data,
    }),

  delete: (id: string) =>
    apiRequest<void>({
      method: 'DELETE',
      url: `/devices/${id}`,
    }),

  getConfig: (id: string, params?: { section?: string; format?: string }) =>
    apiRequest<{ config_block: import('@/types/api').ConfigBlock; merkle_proof: string }>({
      method: 'GET',
      url: `/devices/${id}/config`,
      params,
    }),

  getConfigHistory: (id: string, params?: { from?: string; to?: string; limit?: number }) =>
    apiRequest<{ history: import('@/types/api').ConfigBlock[] }>({
      method: 'GET',
      url: `/devices/${id}/config/history`,
      params,
    }),

  executeOperation: (id: string, data: { action: string; parameters: Record<string, unknown> }) =>
    apiRequest<{ result: unknown; status: string }>({
      method: 'POST',
      url: `/devices/${id}/operations`,
      data,
    }),

  getAttestation: (id: string) =>
    apiRequest<import('@/types/api').AttestationReport>({
      method: 'GET',
      url: `/devices/${id}/attestation`,
    }),
}

// Capabilities API
export const capabilitiesApi = {
  list: (params: { subject_id: string; active?: boolean }) =>
    apiRequest<{ capabilities: import('@/types/api').CapabilityToken[] }>({
      method: 'GET',
      url: '/capabilities',
      params,
    }),

  get: (id: string) =>
    apiRequest<import('@/types/api').CapabilityToken>({
      method: 'GET',
      url: `/capabilities/${id}`,
    }),

  request: (data: {
    resources: Array<{ device_id: string; actions: string[]; constraints?: Record<string, unknown> }>
    validity_duration: string
    justification: string
  }) =>
    apiRequest<import('@/types/api').CapabilityToken>({
      method: 'POST',
      url: '/capabilities/request',
      data,
    }),

  approve: (id: string, data: { approver_signature: string }) =>
    apiRequest<{ status: string; remaining_approvals: number }>({
      method: 'POST',
      url: `/capabilities/${id}/approve`,
      data,
    }),

  revoke: (id: string, reason: string) =>
    apiRequest<void>({
      method: 'DELETE',
      url: `/capabilities/${id}`,
      data: { reason },
    }),
}

// Policies API
export const policiesApi = {
  list: (params?: { type?: string; status?: string; limit?: number; offset?: number }) =>
    apiRequest<{ policies: import('@/types/api').Policy[]; total: number }>({
      method: 'GET',
      url: '/policies',
      params,
    }),

  get: (id: string) =>
    apiRequest<import('@/types/api').Policy>({
      method: 'GET',
      url: `/policies/${id}`,
    }),

  create: (data: Omit<import('@/types/api').Policy, 'id' | 'version' | 'created_at' | 'status'>) =>
    apiRequest<import('@/types/api').Policy>({
      method: 'POST',
      url: '/policies',
      data,
    }),

  update: (id: string, data: Partial<import('@/types/api').Policy>) =>
    apiRequest<import('@/types/api').Policy>({
      method: 'PUT',
      url: `/policies/${id}`,
      data,
    }),

  delete: (id: string) =>
    apiRequest<void>({
      method: 'DELETE',
      url: `/policies/${id}`,
    }),

  evaluate: (data: import('@/types/api').PolicyEvaluationRequest) =>
    apiRequest<import('@/types/api').PolicyDecision>({
      method: 'POST',
      url: '/policies/evaluate',
      data,
    }),

  activate: (id: string) =>
    apiRequest<{ status: string }>({
      method: 'POST',
      url: `/policies/${id}/activate`,
    }),
}

// Configs API
export const configsApi = {
  validate: (data: { device_id: string; configuration: Record<string, unknown>; checks: string[] }) =>
    apiRequest<{ valid: boolean; errors: string[]; warnings: string[] }>({
      method: 'POST',
      url: '/configs/validate',
      data,
    }),

  deploy: (data: {
    targets: Array<{ device_id: string; config_block: Record<string, unknown> }>
    deployment_strategy: 'atomic' | 'rolling' | 'canary'
    verification: Record<string, unknown>
    rollback_on_failure: boolean
  }) =>
    apiRequest<{ deployment_id: string; status: string }>({
      method: 'POST',
      url: '/configs/deploy',
      data,
    }),

  getDeployment: (id: string) =>
    apiRequest<import('@/types/api').Deployment>({
      method: 'GET',
      url: `/configs/deployments/${id}`,
    }),

  approveDeployment: (id: string, data: { approver_signature: string }) =>
    apiRequest<{ status: string; can_proceed: boolean }>({
      method: 'POST',
      url: `/configs/deployments/${id}/approve`,
      data,
    }),

  rollbackDeployment: (id: string, data: { reason: string; target_sequence?: number }) =>
    apiRequest<{ rollback_deployment_id: string }>({
      method: 'POST',
      url: `/configs/deployments/${id}/rollback`,
      data,
    }),
}

// Audit API
export const auditApi = {
  list: (params?: {
    from?: string
    to?: string
    actor?: string
    resource?: string
    action?: string
    event_type?: string
    result?: string
    limit?: number
    offset?: number
  }) =>
    apiRequest<{ events: import('@/types/api').AuditEvent[]; total: number }>({
      method: 'GET',
      url: '/audit/events',
      params,
    }),

  get: (id: string) =>
    apiRequest<import('@/types/api').AuditEvent & { chain_proof: string }>({
      method: 'GET',
      url: `/audit/events/${id}`,
    }),

  verify: (data: { event_id: string; expected_hash?: string }) =>
    apiRequest<{ verified: boolean; chain_proof: string }>({
      method: 'POST',
      url: '/audit/verify',
      data,
    }),
}

// Dashboard API
export const dashboardApi = {
  getStats: () =>
    apiRequest<import('@/types/api').DashboardStats>({
      method: 'GET',
      url: '/dashboard/stats',
    }),
}
