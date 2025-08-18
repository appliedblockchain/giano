import { EIP1474Methods, PublicClient } from "viem"
import { SmartAccount } from 'viem/account-abstraction'
import { ProviderRequestMethod } from '../../provider'
import { SmartAccountDeploymentError, WaitForSmartAccountDeploymentError } from './errors'
import { isSmartAccountDeployed } from './is-smart-account-deployed'
import { waitForSmartAccountDeployment, WaitForSmartAccountDeploymentErrorType } from './wait-for-smart-account-deployment'

/**
 * Ensures that a smart account is deployed on the blockchain.
 * 
 * This function checks if the smart account is already deployed, and if not,
 * it initiates deployment by sending a minimal transaction to the account address.
 * The deployment process uses a simple transaction with zero value and empty data
 * to trigger the account's creation through the account abstraction infrastructure.
 * 
 * @param smartAccount - The smart account instance to deploy. This should be a
 *                       configured SmartAccount that can provide its address and
 *                       deployment information.
 * @param client - The public client instance used to interact with the blockchain.
 *                 This client is used to check deployment status and wait for
 *                 deployment confirmation.
 * @param eth_sendTransaction - The provider method for sending transactions.
 *                              This is used to send the deployment transaction
 *                              that triggers smart account creation.
 * 
 * @returns A Promise that resolves when the smart account is confirmed to be
 *          deployed on the blockchain.
 * 
 * @throws {WaitForSmartAccountDeploymentErrorType} When there's an error during
 *         the deployment waiting process, including timeout errors or deployment
 *         status checking failures.
 * @throws {SmartAccountDeploymentError} When deployment fails for any other
 *         reason, such as transaction sending failures or unexpected errors.
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
 * const sendTransaction = // ... your provider's eth_sendTransaction method
 * 
 * try {
 *   await ensureSmartAccountIsDeployed(smartAccount, client, sendTransaction)
 *   console.log('Smart account is now deployed')
 * } catch (error) {
 *   console.error('Failed to deploy smart account:', error)
 * }
 * ```
 */
export const ensureSmartAccountIsDeployed = async (
  smartAccount: SmartAccount,
  client: PublicClient,
  eth_sendTransaction: ProviderRequestMethod<EIP1474Methods, 'eth_sendTransaction'>,
): Promise<void> => {
  try {
    const isDeployed = await isSmartAccountDeployed(client, smartAccount)

    if (isDeployed) {
      return
    }

    // Send a minimal transaction with zero value and empty data
    // to trigger the account abstraction deployment process
    await eth_sendTransaction([{
      to: await smartAccount.getAddress(),
      value: '0x0',
      data: '0x',
    }])

    // We check the account code directly instead of using the user-op hash
    // to support privacy-enabled bundlers that require signatures for read calls.
    // Since the smart account isn't deployed yet, the bundler can't verify signatures
    // using the smart account's ERC-4337 signature verification logic.
    await waitForSmartAccountDeployment(client, { smartAccount })
  } catch (error) {
    if (error instanceof WaitForSmartAccountDeploymentError) {
      throw error
    }

    throw new SmartAccountDeploymentError(
      'Failed to deploy smart account',
      { cause: error }
    )
  }
}
