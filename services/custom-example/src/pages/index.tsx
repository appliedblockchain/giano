import 'react';
import { toCoinbaseSmartAccount } from '@appliedblockchain/giano-connector';
import { credentialKeyMapperAbi, privateErc20Abi } from '@appliedblockchain/giano-contracts';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import type { NextPage } from 'next';
import Head from 'next/head';
import type { FormEvent } from 'react';
import { useEffect, useState } from 'react';
import type { Address } from 'viem';
import { concatHex, createPublicClient, encodeFunctionData, formatEther, http, keccak256, parseEther, parseGwei } from 'viem';
import { createBundlerClient, createWebAuthnCredential, toSmartAccount, toWebAuthnAccount } from 'viem/account-abstraction';
import { hardhat } from 'viem/chains';
import { useAccount, useReadContract, useWriteContract } from 'wagmi';
import styles from '../styles/Home.module.css';
import { Hex } from 'viem';
import { toHex } from 'viem';

const CREDENTIAL_MAPPER_ADDRESS = '0x2BF3Ec07f07C52df9DE3Ac40e142d64F95762ECB';
const PRIVATE_ERC20_ADDRESS = '0xA6ED5f9baB12B749CD9Dc2ED73320eadb055D9B9';
const PAYMASTER_ADDRESS = '0x0A8285879FD97FBe15f9402fDED9511Ef3Abf04d';
const Home: NextPage = () => {
  const { address, isConnected } = useAccount();
  const { writeContractAsync, isPending: isWritePending } = useWriteContract();
  const {
    refetch: readContract,
    isPending: isReadPending,
    error,
  } = useReadContract({
    address: PRIVATE_ERC20_ADDRESS,
    abi: privateErc20Abi,
    functionName: 'balanceOf',
    args: [address!],
    query: {
      enabled: !!address,
      retry: false,
      retryOnMount: false,
    },
  });

  const [inputMessage, setInputMessage] = useState('');
  const [contractState, setContractState] = useState<bigint | null>(null);
  useEffect(() => {
    if (error) {
      console.error(error);
    }
  }, [error]);

  type PublicKeyAssertion = PublicKeyCredential & { response: AuthenticatorAssertionResponse };

  const sendTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault();
    if (!inputMessage.trim()) return;
    const result = await writeContractAsync({
      address: PRIVATE_ERC20_ADDRESS,
      abi: privateErc20Abi,
      functionName: 'mint',
      args: [parseEther(inputMessage.trim())],
    });
    console.log(result);
  };

  const generateRandomChallenge = () => {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    return challenge;
  };

  const getCredential = async ({
    id,
    challenge,
  }: {
    id?: BufferSource;
    challenge?: BufferSource;
  } = {}): Promise<PublicKeyAssertion | null> => {
    if (!challenge) {
      challenge = generateRandomChallenge();
    }

    try {
      return (await navigator.credentials.get({
        publicKey: {
          ...(id && { allowCredentials: [{ id, type: 'public-key' }] }),
          challenge,
        },
      })) as PublicKeyAssertion | null;
    } catch (error) {
      if (['NotAllowedError', 'AbortError'].includes((error as Error).name)) {
        return null;
      }
      throw error;
    }
  };

  const mint4337 = async () => {
    const credential = await getCredential();
    if (!credential) {
      return;
    }
    const publicClient = createPublicClient({
      chain: hardhat,
      transport: http('http://localhost:8545'),
    });
    const bundlerClient = createBundlerClient({
      transport: http('http://localhost:8080/rpc'),
      client: publicClient,
    });
    const { x, y } = await publicClient.readContract({
      address: CREDENTIAL_MAPPER_ADDRESS,
      abi: credentialKeyMapperAbi,
      functionName: 'getCredentialKey',
      args: [keccak256(new Uint8Array(credential.rawId))],
    });
    const webAuthnAccount = toWebAuthnAccount({
      credential: { id: credential.id, publicKey: concatHex([x, y]) },
    });
    const gianoAccount = await toCoinbaseSmartAccount({
      client: publicClient,
      owners: [webAuthnAccount],
    });
    const op = {
      account: gianoAccount,
      paymaster: PAYMASTER_ADDRESS as Address,
      callGasLimit: 0n, // added here because the schema requires it, but this will be calculated by the bundler
      paymasterPostOpGasLimit: 100_000n, // can this be calculated somehow?
      paymasterVerificationGasLimit: 100_000n,
      calls: [
        {
          to: PRIVATE_ERC20_ADDRESS as Address,
          value: 0n,
          data: encodeFunctionData({
            abi: privateErc20Abi,
            functionName: 'mint',
            args: [parseEther('20')],
          }),
        },
      ],
    };
    const estimate = await bundlerClient.estimateUserOperationGas(op);
    console.log({ estimate });
    const prepared = await bundlerClient.prepareUserOperation({
      ...op,
      ...estimate,
    });
    const finalOp = {
      ...prepared,
      preVerificationGas: prepared.preVerificationGas + 1000n, // safety margin
      maxFeePerGas: parseGwei('200'),
      maxPriorityFeePerGas: parseGwei('400'),
    };
    const signature = await gianoAccount.signUserOperation(finalOp);
    const hash = await bundlerClient.sendUserOperation({
      ...finalOp,
      signature,
    });

    const receipt = await bundlerClient.waitForUserOperationReceipt({ hash });

    console.log({ receipt });
  };

  function extractXYCoords(key: Uint8Array | Hex): { x: Hex; y: Hex } {
    if (key instanceof Uint8Array) {
      key = toHex(key.slice(-64), { size: 64 });
    }
    return { x: `0x${key.slice(-128, -64)}`, y: `0x${key.slice(-64)}` };
  }

  const createCredential = async () => {
    const challenge = new Uint8Array();
    crypto.getRandomValues(challenge);
    const credential = await createWebAuthnCredential({ name: 'Giano' });
    const owner = toWebAuthnAccount({ credential });
    const publicClient = createPublicClient({
      chain: hardhat,
      transport: http('http://localhost:8545'),
    });
    const gianoAccount = await toCoinbaseSmartAccount({ client: publicClient, owners: [owner] });
    console.log({ address: gianoAccount.address });
    const bundlerClient = createBundlerClient({
      transport: http('http://localhost:8080/rpc'),
      client: publicClient,
    });
    const smartAccount = await toSmartAccount(gianoAccount);
    const { x, y } = extractXYCoords(credential.publicKey);
    const op = {
      account: smartAccount,
      paymaster: PAYMASTER_ADDRESS as Address,
      callGasLimit: 0n, // added here because the schema requires it, but this will be calculated by the bundler
      paymasterPostOpGasLimit: 100_000n, // can this be calculated somehow?
      paymasterVerificationGasLimit: 100_000n,
      calls: [
        {
          to: CREDENTIAL_MAPPER_ADDRESS as Address,
          value: 0n,
          data: encodeFunctionData({
            abi: credentialKeyMapperAbi,
            functionName: 'setCredentialKey',
            args: [keccak256(new Uint8Array(credential.raw.rawId)), { x, y }],
          }),
        },
      ],
    };
    const estimate = await bundlerClient.estimateUserOperationGas(op);
    console.log({ estimate });
    const prepared = await bundlerClient.prepareUserOperation({
      ...op,
      ...estimate,
    });
    const finalOp = {
      ...prepared,
      preVerificationGas: prepared.preVerificationGas + 1000n, // safety margin
      maxFeePerGas: parseGwei('200'),
      maxPriorityFeePerGas: parseGwei('400'),
    };
    const signature = await smartAccount.signUserOperation(finalOp);
    const hash = await bundlerClient.sendUserOperation({
      ...finalOp,
      signature,
    });

    const receipt = await bundlerClient.waitForUserOperationReceipt({ hash });

    console.log({ receipt });

    const key = await publicClient.readContract({
      abi: credentialKeyMapperAbi,
      address: CREDENTIAL_MAPPER_ADDRESS,
      functionName: 'getCredentialKey',
      args: [keccak256(new Uint8Array(credential.raw.rawId))],
    });
    console.log({ key });
  };

  const sendCall = async () => {
    const { data } = await readContract();
    if (data) setContractState(data);
  };

  return (
    <div className={styles.container}>
      <Head>
        <title>Giano Demo</title>
        <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
        <link href="/favicon.ico" rel="icon" />
      </Head>

      <main className={styles.main}>
        <ConnectButton />
        <button className={styles.sendButton} onClick={createCredential}>
          Create ERC-4337 Account
        </button>
        <button className={styles.sendButton} onClick={mint4337}>
          Mint using 4337
        </button>
        <form className={styles.formContainer} onSubmit={sendTx}>
          <input className={styles.input} type="number" placeholder="Enter amount" value={inputMessage} onChange={(e) => setInputMessage(e.target.value)} />
          <button
            className={styles.sendButton}
            // disabled={!isConnected || isWritePending || !inputMessage.trim()}
          >
            Mint
          </button>
        </form>
        <button className={styles.readButton} disabled={!isConnected || isReadPending} onClick={sendCall}>
          Read balance
        </button>

        {contractState && (
          <div className={styles.stateCard}>
            <p>
              <strong>Balance:</strong> {formatEther(contractState)}
            </p>
          </div>
        )}
        {error && <p>Error reading balance: {error.message}</p>}
      </main>
    </div>
  );
};

export default Home;
