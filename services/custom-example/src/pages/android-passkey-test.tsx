import type { NextPage } from 'next';
import Head from 'next/head';
import React, { useEffect, useState } from 'react';
import { createWebAuthnCredential } from 'viem/account-abstraction';

const AndroidPasskeyTest: NextPage = () => {
  const [mounted, setMounted] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [result, setResult] = useState<string>('');
  const [error, setError] = useState<string>('');

  // Effect to handle hydration
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  const createPasskey = async () => {
    setIsCreating(true);
    setResult('');
    setError('');

    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const userId = new TextEncoder().encode(`android-test-${Date.now()}-${Math.random()}`);

      console.log('Creating WebAuthn credential...');

      const credential = await createWebAuthnCredential({
        rp: {
          name: 'Giano Android Passkey Test',
          id: window.location.hostname,
        },
        user: {
          id: userId,
          name: `android-test-${Date.now()}`,
          displayName: `Android Test User ${Date.now()}`,
        },
        challenge,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
          userVerification: 'required',
          residentKey: 'required',
        },
        timeout: 60000,
      });

      const successMessage = `✅ Passkey created successfully!
ID: ${credential.id}
Raw ID Length: ${credential.raw.rawId.byteLength} bytes
Type: ${(credential as any).type || 'unknown'}
Authenticator Attachment: ${credential.raw.authenticatorAttachment || 'not specified'}
Client Data JSON: ${credential.raw.response.clientDataJSON ? 'present' : 'missing'}
Attestation Object: ${(credential.raw.response as any).attestationObject ? 'present' : 'missing'}`;

      setResult(successMessage);
      console.log('Credential created successfully:', credential);
    } catch (err: any) {
      const errorMessage = `❌ Failed to create passkey:
Error Name: ${err.name || 'Unknown'}
Error Message: ${err.message || 'No message provided'}
Error Code: ${err.code || 'No code provided'}
Stack Trace: ${err.stack || 'No stack trace available'}
Full Error: ${JSON.stringify(err, null, 2)}

User Agent: ${navigator.userAgent}
Platform: ${navigator.platform || 'Unknown'}
WebAuthn Support: ${window.PublicKeyCredential ? 'Yes' : 'No'}`;

      setError(errorMessage);
      console.error('Failed to create passkey:', err);
    } finally {
      setIsCreating(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      alert('Copied to clipboard!');
    } catch (err) {
      console.error('Failed to copy:', err);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      alert('Copied to clipboard (fallback method)!');
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        padding: '0 1rem',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'flex-start',
        alignItems: 'center',
      }}
    >
      <Head>
        <title>Android Passkey Test - Giano</title>
        <meta name="description" content="Simple Android passkey compatibility test" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link rel="icon" href="/favicon.ico" />
        <style jsx>{`
          @media (min-width: 640px) {
            .success-header,
            .error-header {
              flex-direction: row !important;
              align-items: center !important;
            }
          }
        `}</style>
      </Head>

      <main
        style={{
          padding: '2rem 0',
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'flex-start',
          alignItems: 'center',
          width: '100%',
          maxWidth: '800px',
        }}
      >
        <h1
          style={{
            fontSize: 'clamp(1.5rem, 5vw, 2.5rem)',
            marginBottom: '1rem',
            textAlign: 'center',
            color: '#333',
          }}
        >
          Android Passkey Test
        </h1>

        <p
          style={{
            fontSize: 'clamp(1rem, 3vw, 1.2rem)',
            textAlign: 'center',
            marginBottom: '2rem',
            color: '#666',
            lineHeight: '1.5',
          }}
        >
          Simple test for WebAuthn passkey creation on Android devices
        </p>

        <div style={{ margin: '2rem 0', textAlign: 'center' }}>
          <button
            onClick={createPasskey}
            disabled={isCreating}
            style={{
              padding: '1rem 2rem',
              fontSize: 'clamp(1rem, 4vw, 1.2rem)',
              backgroundColor: isCreating ? '#ccc' : '#0070f3',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              cursor: isCreating ? 'not-allowed' : 'pointer',
              minWidth: '200px',
              width: '100%',
              maxWidth: '300px',
              minHeight: '48px',
            }}
          >
            {isCreating ? 'Creating Passkey...' : 'Create Passkey'}
          </button>
        </div>

        {result && (
          <div
            style={{
              margin: '1rem 0',
              padding: '1rem',
              backgroundColor: '#d4edda',
              border: '1px solid #c3e6cb',
              borderRadius: '8px',
              fontFamily: 'monospace',
              fontSize: 'clamp(0.75rem, 2.5vw, 0.9rem)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              overflowWrap: 'break-word',
            }}
          >
            <div
              style={{
                marginBottom: '1rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                alignItems: 'stretch',
                gap: '0.5rem',
              }}
              className="success-header"
            >
              <strong style={{ color: '#155724', fontSize: 'clamp(0.9rem, 3vw, 1.1rem)' }}>
                Success Result:
              </strong>
              <button
                onClick={() => copyToClipboard(result)}
                style={{
                  padding: '0.75rem 1rem',
                  fontSize: 'clamp(0.85rem, 3vw, 0.9rem)',
                  backgroundColor: '#28a745',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  minHeight: '44px',
                }}
              >
                Copy Result
              </button>
            </div>
            <div style={{ color: '#155724', lineHeight: '1.4' }}>{result}</div>
          </div>
        )}

        {error && (
          <div
            style={{
              margin: '1rem 0',
              padding: '1rem',
              backgroundColor: '#f8d7da',
              border: '1px solid #f5c6cb',
              borderRadius: '8px',
              fontFamily: 'monospace',
              fontSize: 'clamp(0.75rem, 2.5vw, 0.9rem)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              overflowWrap: 'break-word',
            }}
          >
            <div
              style={{
                marginBottom: '1rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                alignItems: 'stretch',
                gap: '0.5rem',
              }}
              className="error-header"
            >
              <strong style={{ color: '#721c24', fontSize: 'clamp(0.9rem, 3vw, 1.1rem)' }}>
                Error Details:
              </strong>
              <button
                onClick={() => copyToClipboard(error)}
                style={{
                  padding: '0.75rem 1rem',
                  fontSize: 'clamp(0.85rem, 3vw, 0.9rem)',
                  backgroundColor: '#dc3545',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  minHeight: '44px',
                }}
              >
                Copy Error
              </button>
            </div>
            <div style={{ color: '#721c24', lineHeight: '1.4' }}>{error}</div>
          </div>
        )}

        <div
          style={{
            margin: '1rem 0',
            padding: '1rem',
            backgroundColor: '#e2e3e5',
            border: '1px solid #d6d8db',
            borderRadius: '8px',
            fontSize: 'clamp(0.7rem, 2.2vw, 0.85rem)',
            fontFamily: 'monospace',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            overflowWrap: 'break-word',
            lineHeight: '1.4',
          }}
        >
          <strong style={{ fontSize: 'clamp(0.8rem, 2.5vw, 1rem)' }}>Test Environment Info:</strong>
          <br />
          User Agent: {navigator.userAgent}
          <br />
          Platform: {navigator.platform || 'Unknown'}
          <br />
          Hostname: {typeof window !== 'undefined' ? window.location.hostname : 'Unknown'}
          <br />
          <br />
          <strong style={{ fontSize: 'clamp(0.8rem, 2.5vw, 1rem)' }}>WebAuthn Capability Checks:</strong>
          <br />
          window.PublicKeyCredential:{' '}
          {typeof window !== 'undefined' && window.PublicKeyCredential ? 'Available ✅' : 'Missing ❌'}
          <br />
          navigator.credentials:{' '}
          {typeof navigator !== 'undefined' && navigator.credentials ? 'Available ✅' : 'Missing ❌'}
          <br />
          navigator.credentials.create:{' '}
          {typeof navigator !== 'undefined' &&
          navigator.credentials &&
          typeof navigator.credentials.create === 'function'
            ? 'Available ✅'
            : 'Missing ❌'}
          <br />
          navigator.credentials.get:{' '}
          {typeof navigator !== 'undefined' &&
          navigator.credentials &&
          typeof navigator.credentials.get === 'function'
            ? 'Available ✅'
            : 'Missing ❌'}
          <br />
          PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable:{' '}
          {typeof window !== 'undefined' &&
          window.PublicKeyCredential &&
          typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function'
            ? 'Available ✅'
            : 'Missing ❌'}
          <br />
          <br />
          <strong style={{ fontSize: 'clamp(0.8rem, 2.5vw, 1rem)' }}>Browser Info:</strong>
          <br />
          Is Secure Context (HTTPS):{' '}
          {typeof window !== 'undefined' && window.isSecureContext ? 'Yes ✅' : 'No ❌'}
          <br />
          Is Cross-Origin Isolated:{' '}
          {typeof window !== 'undefined' && window.crossOriginIsolated ? 'Yes ✅' : 'No ❌'}
        </div>
      </main>
    </div>
  );
};

export default AndroidPasskeyTest; 