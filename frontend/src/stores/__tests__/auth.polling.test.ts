import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '../auth'
import { getQRCodeStatus, generateQRCode } from '@/api/auth'
import type { QRCodeStatus } from '@/api/auth'

vi.mock('@/api/auth', () => ({
  getQRCodeStatus: vi.fn(), generateQRCode: vi.fn(), getCurrentUser: vi.fn(),
  logout: vi.fn(), cookieLogin: vi.fn(), cancelQRCode: vi.fn().mockResolvedValue(undefined),
}))
const qr = (sign: string) => ({ sign, image_base64: '', qrcode_url: '', created_at: 0 })

describe('QR polling lifecycle', () => {
  beforeEach(() => { setActivePinia(createPinia()); vi.useFakeTimers(); vi.clearAllMocks() })
  afterEach(() => vi.useRealTimers())

  it('waits for a slow request before scheduling the next poll', async () => {
    let finish!: (value: QRCodeStatus) => void
    vi.mocked(getQRCodeStatus).mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    vi.mocked(getQRCodeStatus).mockResolvedValue({ status: 'waiting' })
    const store = useAuthStore(); store.qrcode = qr('a')
    store.startPolling(vi.fn(), vi.fn())
    await vi.advanceTimersByTimeAsync(15000)
    expect(getQRCodeStatus).toHaveBeenCalledTimes(1)
    finish({ status: 'initializing' }); await vi.advanceTimersByTimeAsync(2999)
    expect(getQRCodeStatus).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(getQRCodeStatus).toHaveBeenCalledTimes(2)
    store.stopPolling()
  })

  it('ignores a late success after refresh and cancels the previous timer', async () => {
    let finish!: (value: QRCodeStatus) => void
    vi.mocked(getQRCodeStatus).mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    vi.mocked(generateQRCode).mockResolvedValue(qr('b'))
    const store = useAuthStore(); store.qrcode = qr('a')
    const success = vi.fn(); store.startPolling(success, vi.fn())
    await store.generateQRCode()
    finish({ status: 'success', user: { uid: 99, username: 'synthetic', login_time: 0 } }); await vi.advanceTimersByTimeAsync(9000)
    expect(success).not.toHaveBeenCalled()
    expect(store.user).toBeNull()
    expect(store.qrcode?.sign).toBe('b')
    expect(getQRCodeStatus).toHaveBeenCalledTimes(1)
  })

  it('stops with a useful initialization error instead of polling forever', async () => {
    vi.mocked(getQRCodeStatus).mockRejectedValue(new Error('初始化超时，请重试'))
    const store = useAuthStore(); store.qrcode = qr('a'); const error = vi.fn()
    store.startPolling(vi.fn(), error)
    await vi.advanceTimersByTimeAsync(9000)
    expect(error).toHaveBeenCalledOnce()
    expect(store.isPolling).toBe(false)
    expect(getQRCodeStatus).toHaveBeenCalledOnce()
  })
})
