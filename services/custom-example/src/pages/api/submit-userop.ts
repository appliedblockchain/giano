import type { NextApiRequest, NextApiResponse } from 'next';
import { config } from '../../config';

// Simple counter for unique RPC IDs
let rpcIdCounter = 0;

// Helper function to convert decimal string to hex
function toHex(value: string | number | bigint): string {
  if (typeof value === 'string' && value.startsWith('0x')) {
    return value;
  }
  return '0x' + BigInt(value).toString(16);
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const signedUserOp = req.body;

    console.log('Backend validating and submitting UserOp:', signedUserOp);

    // Step 1: Validation
    if (!signedUserOp.sender || !signedUserOp.signature) {
      return res.status(400).json({ error: 'Invalid user operation format' });
    }

    const maxGasLimit = BigInt('1000000'); // 1M gas
    if (BigInt(signedUserOp.callGasLimit || 0) > maxGasLimit) {
      return res.status(400).json({ error: 'Gas limit too high' });
    }

    console.log('UserOp validation passed, submitting to bundler...');

    // Step 2: Extract user operation data with proper hex formatting
    const userOpData = {
      sender: signedUserOp.sender,
      nonce: toHex(signedUserOp.nonce),
      callData: signedUserOp.callData,
      callGasLimit: toHex(signedUserOp.callGasLimit),
      verificationGasLimit: toHex(signedUserOp.verificationGasLimit),
      preVerificationGas: toHex(signedUserOp.preVerificationGas),
      maxFeePerGas: toHex(signedUserOp.maxFeePerGas),
      maxPriorityFeePerGas: toHex(signedUserOp.maxPriorityFeePerGas),
      signature: signedUserOp.signature,
      ...(signedUserOp.paymaster && { paymaster: signedUserOp.paymaster }),
      ...(signedUserOp.paymasterVerificationGasLimit && { paymasterVerificationGasLimit: toHex(signedUserOp.paymasterVerificationGasLimit) }),
      ...(signedUserOp.paymasterPostOpGasLimit && { paymasterPostOpGasLimit: toHex(signedUserOp.paymasterPostOpGasLimit) }),
      ...(signedUserOp.paymasterData && { paymasterData: signedUserOp.paymasterData }),
      ...(signedUserOp.factory && { factory: signedUserOp.factory }),
      ...(signedUserOp.factoryData && { factoryData: signedUserOp.factoryData }),
    };

    // Extract entryPoint address
    const entryPointAddress = signedUserOp.account?.entryPoint?.address;
    if (!entryPointAddress) {
      return res.status(400).json({ error: 'Missing entryPoint address' });
    }

    // Step 3: Direct RPC call to bundler
    const sendUserOpId = ++rpcIdCounter;
    const rpcResponse = await fetch(config.bundlerRpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: sendUserOpId,
        method: 'eth_sendUserOperation',
        params: [userOpData, entryPointAddress],
      }),
    });

    const rpcResult = await rpcResponse.json();

    if (rpcResult.error) {
      throw new Error(`Bundler RPC error: ${rpcResult.error.message}`);
    }

    const hash = rpcResult.result;
    console.log('UserOp submitted with hash:', hash);

    // Return just the hash - let the frontend handle waiting for receipt
    res.status(200).json({
      success: true,
      hash,
      message: 'User operation submitted successfully',
    });
  } catch (error) {
    console.error('UserOp submission error:', error);
    res.status(500).json({
      error: 'Submission failed',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}