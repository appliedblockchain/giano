import { PublicClient } from 'viem'
import { SmartAccount } from 'viem/account-abstraction'

/**
 * Checks whether a smart account is deployed on the blockchain.
 * 
 * This function determines deployment status by examining the bytecode at the
 * smart account's address. A smart account is considered deployed if there is
 * non-empty bytecode at its address (anything other than undefined or '0x').
 * 
 * @param client - The public client instance used to interact with the blockchain.
 *                 This client is used to fetch the bytecode at the smart account's
 *                 address.
 * @param smartAccount - The smart account instance to check for deployment.
 *                       The function will get the account's address and check
 *                       if bytecode exists at that address.
 * 
 * @returns A Promise that resolves to `true` if the smart account is deployed
 *          (has bytecode at its address), `false` otherwise.
 * 
 * @throws May throw errors from the underlying client operations, such as:
 *         - Network connectivity issues
 *         - Invalid address errors
 *         - RPC provider errors
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
 * const isDeployed = await isSmartAccountDeployed(client, smartAccount)
 * 
 * if (isDeployed) {
 *   console.log('Smart account is already deployed')
 * } else {
 *   console.log('Smart account needs to be deployed')
 * }
 * ```
 */
export const isSmartAccountDeployed = async (
  client: PublicClient,
  smartAccount: SmartAccount,
): Promise<boolean> => {
  const address = await smartAccount.getAddress()
  const code = await client!.getCode({ address })

  return code !== undefined && code !== '0x'
}
