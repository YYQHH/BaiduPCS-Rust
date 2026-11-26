import { describe, expect, it, vi } from 'vitest'
import type { AxiosError } from 'axios'

const hooks = vi.hoisted(() => ({ reject: null as ((error: AxiosError) => Promise<never>) | null }))
vi.mock('axios', () => ({
  default: { create: () => ({
    interceptors: { response: { use: (_resolve: unknown, reject: typeof hooks.reject) => { hooks.reject = reject } } },
  }) },
}))
vi.mock('@/api/client', () => ({ addWebAuthInterceptor: vi.fn() }))
import '../auth'

describe('authentication transport error redaction', () => {
  it('does not propagate Axios request configuration or credentials into logs', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const error = { response: { status: 502 }, config: {
      url: '/qrcode/status?sign=synthetic-secret-sign', data: 'BDUSS=synthetic-secret-cookie',
    } } as AxiosError
    const safe = await hooks.reject!(error).catch(value => value as Error)
    expect(safe.message).toContain('HTTP 502')
    expect(safe).not.toHaveProperty('config')
    expect(JSON.stringify(log.mock.calls)).not.toContain('synthetic-secret')
    log.mockRestore()
  })

  it('keeps timeouts distinguishable without exposing their request URL', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    await expect(hooks.reject!({ code: 'ECONNABORTED' } as AxiosError)).rejects.toThrow('认证请求超时')
    log.mockRestore()
  })
})
