import { PublicClient } from 'viem'
import { SmartAccount } from 'viem/account-abstraction'
import {
  WaitForSmartAccountDeploymentError,
  WaitForSmartAccountDeploymentTimeoutError,
} from './errors'
import { isSmartAccountDeployed } from './is-smart-account-deployed'

const DEFAULT_TIMEOUT_MS = 120_000

export type WaitForSmartAccountDeploymentParameters = {
  /** The smart account to wait for. */
  smartAccount: SmartAccount
  /**
   * Polling frequency (in ms). Defaults to the client's pollingInterval config.
   * @default client.pollingInterval
   */
  pollingInterval?: number | undefined
  /**
   * Optional timeout (in ms) to wait before stopping polling.
   * Defaults to {@link DEFAULT_TIMEOUT_MS}.
   */
  timeout?: number | undefined
}

/**
 * Waits for a smart account to be deployed on the blockchain using polling.
 * 
 * This function continuously polls the blockchain to check if the smart account
 * has been deployed by examining its bytecode. It will poll immediately upon
 * calling, then continue polling at the specified interval until either the
 * account is deployed, an error occurs, or the timeout is reached.
 * 
 * @param client - The public client instance used to interact with the blockchain.
 *                 The client's pollingInterval is used as the default polling frequency.
 * @param parameters - Configuration object containing the smart account to wait for
 *                     and optional polling/timeout settings.
 * 
 * @returns A Promise that resolves when the smart account is confirmed to be
 *          deployed on the blockchain (has bytecode at its address).
 * 
 * @throws {WaitForSmartAccountDeploymentTimeoutError} When the specified timeout
 *         is reached before the smart account is deployed.
 * @throws {WaitForSmartAccountDeploymentError} When there's an error checking
 *         the deployment status during the polling process.
 * 
 * @example
 * ```typescript
 * import { createPublicClient, http } from 'viem'
 * import { mainnet } from 'viem/chains'
 * 
 * const client = createPublicClient({
 *   chain: mainnet,
 *   transport: http()
 * })
 * 
 * const smartAccount = // ... your configured smart account
 * 
 * try {
 *   // Wait with default settings (default timeout, client's polling interval)
 *   await waitForSmartAccountDeployment(client, { smartAccount })
 *   console.log('Smart account deployment confirmed')
 * 
 *   // Wait with custom settings
 *   await waitForSmartAccountDeployment(client, {
 *     smartAccount,
 *     pollingInterval: 1000, // Check every second
 *     timeout: 60000 // 1 minute timeout
 *   })
 * } catch (error) {
 *   if (error instanceof WaitForSmartAccountDeploymentTimeoutError) {
 *     console.error('Deployment timed out after', error.timeout, 'ms')
 *   } else {
 *     console.error('Failed to wait for deployment:', error)
 *   }
 * }
 * ```
 */
export function waitForSmartAccountDeployment(
  client: PublicClient,
  parameters: WaitForSmartAccountDeploymentParameters,
): Promise<void> {
  const {
    smartAccount,
    pollingInterval = client.pollingInterval,
    timeout = DEFAULT_TIMEOUT_MS,
  } = parameters

  let timeoutId: ReturnType<typeof setTimeout> | undefined
  let intervalId: ReturnType<typeof setInterval> | undefined

  const cleanup = () => {
    if (timeoutId) clearTimeout(timeoutId)
    if (intervalId) clearInterval(intervalId)
  }

  return new Promise((resolve, reject) => {
    if (timeout) {
      timeoutId = setTimeout(() => {
        cleanup()
        reject(new WaitForSmartAccountDeploymentTimeoutError(timeout))
      }, timeout)
    }

    const poll = async () => {
      try {
        const isDeployed = await isSmartAccountDeployed(client, smartAccount)
        
        if (isDeployed) {
          cleanup()
          resolve()
          return
        }
      } catch (error) {
        cleanup()
        reject(new WaitForSmartAccountDeploymentError(
          'Failed to check smart account deployment status',
          { cause: error }
        ))
      }
    }

    poll()
    intervalId = setInterval(poll, pollingInterval)
  })
}

export type WaitForSmartAccountDeploymentErrorType =
  | WaitForSmartAccountDeploymentError
  | WaitForSmartAccountDeploymentTimeoutError
