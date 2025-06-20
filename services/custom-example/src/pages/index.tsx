import { privateErc20Abi } from '@appliedblockchain/giano-contracts'
import type { NextPage } from 'next'
import Head from 'next/head'
import React, { type FormEvent } from 'react'
import { useEffect, useState } from 'react'
import { formatEther, parseEther } from 'viem'
import {
  useAccount,
  useConnect,
  useDisconnect,
  useReadContract,
  useWalletClient,
  useWriteContract,
} from 'wagmi'
import styles from '../styles/Home.module.css'
import { gianoConnector } from '../wagmi'

const PRIVATE_ERC20_ADDRESS = '0xA6ED5f9baB12B749CD9Dc2ED73320eadb055D9B9'

const Home: NextPage = () => {
  const [mounted, setMounted] = useState(false)
  const [connectionReady, setConnectionReady] = useState(false)
  const { connect } = useConnect()
  const { disconnect } = useDisconnect()
  const { address, isConnected, status } = useAccount()
  const { data: walletClient } = useWalletClient()
  const { writeContractAsync, isPending: isWritePending } = useWriteContract()
  const {
    refetch: readContract,
    isFetching: isReadFetching,
    error,
  } = useReadContract({
    address: PRIVATE_ERC20_ADDRESS,
    abi: privateErc20Abi,
    functionName: 'balanceOf',
    args: [address!],
    query: {
      enabled: false,
      retry: false,
      retryOnMount: false,
    },
  })

  const [inputMessage, setInputMessage] = useState('')
  const [contractState, setContractState] = useState<bigint | null>(null)
  const [signatureResult, setSignatureResult] = useState<string>('')
  const [messageToSign, setMessageToSign] = useState('Hello, please sign this message!')

  useEffect(() => {
    setMounted(true)
  }, [])

  // Auto-connect effect for session restoration
  useEffect(() => {
    if (mounted && !isConnected) {
      const storedCredentialId = localStorage.getItem('giano_credential_id')
      const storedAccountAddress = localStorage.getItem('giano_account_address')
      
      if (storedCredentialId && storedAccountAddress) {
        // Attempt to restore session
        const connectAsync = async () => {
          try {
            await connect({ connector: gianoConnector })
          } catch (error) {
            console.warn('Failed to auto-restore session:', error)
            // Clear invalid stored data
            localStorage.removeItem('giano_credential_id')
            localStorage.removeItem('giano_account_address')
          }
        }
        connectAsync()
      }
    }
  }, [mounted, isConnected, connect])

  // Wait for the connection to be fully established before allowing contract calls
  useEffect(() => {
    if (isConnected && address && status === 'connected') {
      // Add a small delay to ensure the smart account is fully initialized
      const timer = setTimeout(() => {
        setConnectionReady(true)
      }, 500)
      return () => clearTimeout(timer)
    } else {
      setConnectionReady(false)
    }
  }, [isConnected, address, status])

  useEffect(() => {
    if (error) {
      console.error(error)
    }
  }, [error])

  const sendTx = async (e: FormEvent & { currentTarget: HTMLFormElement }) => {
    e.preventDefault()
    if (!inputMessage.trim()) return
    const result = await writeContractAsync({
      address: PRIVATE_ERC20_ADDRESS,
      abi: privateErc20Abi,
      functionName: 'mint',
      args: [parseEther(inputMessage.trim())],
    })
  }

  const sendCall = async () => {
    const { data } = await readContract()
    if (data) setContractState(data)
  }
  
  const signMessage = async () => {
    if (!walletClient || !address) {
      console.error('Wallet not connected')
      return
    }

    try {
      const signature = await walletClient.signMessage({
        message: messageToSign,
      } as any)
      setSignatureResult(signature as string)
      console.log('Message signed successfully:', signature)
    } catch (error) {
      console.error('Message signing failed:', error)
      setSignatureResult('Error: ' + (error as Error).message)
    }
  }

  const signTypedData = async () => {
    if (!walletClient || !address) {
      console.error('Wallet not connected')
      return
    }

    try {
      // Example EIP-712 typed data
      const typedData = {
        domain: {
          name: 'Giano Demo',
          version: '1',
          chainId: 1,
          verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        },
        types: {
          Message: [
            { name: 'content', type: 'string' },
            { name: 'timestamp', type: 'uint256' },
          ],
        },
        primaryType: 'Message',
        message: {
          content: 'Hello from Giano!',
          timestamp: Math.floor(Date.now() / 1000),
        },
      }

      const signature = await walletClient.request({
        method: 'eth_signTypedData_v4',
        params: [address, JSON.stringify(typedData)],
      } as any)
      
      setSignatureResult(signature as string)
      console.log('Typed data signed successfully:', signature)
    } catch (error) {
      console.error('Typed data signing failed:', error)
      setSignatureResult('Error: ' + (error as Error).message)
    }
  }

  // Don't render wallet-dependent UI until after hydration
  if (!mounted) {
    return (
      <div className={styles.container}>
        <Head>
          <title>Giano Demo</title>
          <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
          <link href="/favicon.ico" rel="icon" />
        </Head>
        <main className={styles.main}>
          <div>Loading...</div>
        </main>
      </div>
    )
  }

  return (
    <div className={styles.container}>
      <Head>
        <title>Giano Demo</title>
        <meta content="Generated by @rainbow-me/create-rainbowkit" name="description" />
        <link href="/favicon.ico" rel="icon" />
      </Head>

      <main className={styles.main}>
        {isConnected
          ? <button onClick={() => disconnect()}>Disconnect</button>
          : <button onClick={() => connect({ connector: gianoConnector })}>Connect</button>
        }
        <form className={styles.formContainer} onSubmit={sendTx}>
          <input className={styles.input} type="number" placeholder="Enter amount" value={inputMessage} onChange={(e) => setInputMessage(e.target.value)} />
          <button className={styles.sendButton} disabled={isWritePending || !inputMessage.trim()}>
            Mint
          </button>
        </form>
        <button
          className={styles.readButton}
          disabled={
            !address ||
            !mounted ||
            !connectionReady ||
            !isConnected ||
            isReadFetching
          }
          onClick={sendCall}
        >
          Read balance
        </button>

        {/* Message Signing Section */}
        <div className={styles.formContainer}>
          <input 
            className={styles.input} 
            type="text" 
            placeholder="Message to sign" 
            value={messageToSign} 
            onChange={(e) => setMessageToSign(e.target.value)} 
          />
          <button 
            className={styles.readButton} 
            disabled={!isConnected} 
            onClick={signMessage}
          >
            Sign Message (Personal)
          </button>
          <button 
            className={styles.readButton} 
            disabled={!isConnected} 
            onClick={signTypedData}
          >
            Sign Typed Data (EIP-712)
          </button>
        </div>

        {contractState && (
          <div className={styles.stateCard}>
            <p>
              <strong>Balance:</strong> {formatEther(contractState)}
            </p>
          </div>
        )}

        {signatureResult && (
          <div className={styles.stateCard}>
            <p>
              <strong>Signature:</strong>
            </p>
            <p style={{ wordBreak: 'break-all', fontSize: '0.8em' }}>
              {signatureResult}
            </p>
          </div>
        )}

        {error && <p>Error reading balance: {error.message}</p>}
      </main>
    </div>
  )
}

export default Home
