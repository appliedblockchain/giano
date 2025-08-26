import type { NextPage } from 'next';
import Head from 'next/head';
import React, { useCallback, useEffect, useState } from 'react';
import styles from '../styles/Home.module.css';

const RelatedOriginRequestsDemo: NextPage = () => {
  const [mounted, setMounted] = useState(false);

  // ROR specific state
  const [browserSupportsROR, setBrowserSupportsROR] = useState<boolean | null>(null);
  const [currentOrigin, setCurrentOrigin] = useState('');
  const [targetDomainForWellKnown, setTargetDomainForWellKnown] = useState('');
  const [passkeyRpId, setPasskeyRpId] = useState('');
  const [passkeyName, setPasskeyName] = useState('');
  const [isCreatingCrossOriginPasskey, setIsCreatingCrossOriginPasskey] = useState(false);
  const [crossOriginPasskeyCreated, setCrossOriginPasskeyCreated] = useState(false);
  const [crossOriginPasskeyInfo, setCrossOriginPasskeyInfo] = useState<{
    id: string;
    rpId: string;
    origin: string;
    rawId: ArrayBuffer;
    name: string;
  } | null>(null);
  const [isTestingCrossOrigin, setIsTestingCrossOrigin] = useState(false);
  const [crossOriginTestResult, setCrossOriginTestResult] = useState<{
    success: boolean;
    error?: string;
    credentialId?: string;
    rpId?: string;
    origin?: string;
  } | null>(null);
  const [wellKnownStatus, setWellKnownStatus] = useState<{
    checked: boolean;
    exists: boolean;
    content?: any;
    error?: string;
  }>({ checked: false, exists: false });

  // New state for .well-known management
  const [isUpdatingWellKnown, setIsUpdatingWellKnown] = useState(false);
  const [wellKnownConfig, setWellKnownConfig] = useState<{ origins: string[] }>({ origins: [] });

  // Check browser support for ROR
  const checkBrowserSupport = useCallback(async () => {
    try {
      // Check if getClientCapabilities is available (not yet implemented in browsers as of August 2024)
      if ('getClientCapabilities' in PublicKeyCredential) {
        // Future API when available
        const capabilities = await (PublicKeyCredential as any).getClientCapabilities();
        setBrowserSupportsROR(capabilities?.relatedOrigins === true);
      } else {
        // Fallback: detect based on user agent
        const userAgent = navigator.userAgent;
        const isChrome = userAgent.includes('Chrome');
        const isSafari = userAgent.includes('Safari') && !userAgent.includes('Chrome');
        const isFirefox = userAgent.includes('Firefox');

        if (isChrome) {
          // Chrome 128+ supports ROR
          const chromeMatch = userAgent.match(/Chrome\/(\d+)/);
          const chromeVersion = chromeMatch ? parseInt(chromeMatch[1]) : 0;
          setBrowserSupportsROR(chromeVersion >= 128);
        } else if (isSafari) {
          // Safari macOS 15+ / iOS 18+ supports ROR
          setBrowserSupportsROR(null); // Unknown, need to test
        } else if (isFirefox) {
          setBrowserSupportsROR(false); // Firefox doesn't support it yet
        } else {
          setBrowserSupportsROR(null); // Unknown browser
        }
      }
    } catch (error) {
      console.error('Error checking browser support:', error);
      setBrowserSupportsROR(null);
    }
  }, []);

  // Check .well-known/webauthn file
  const checkWellKnownFile = useCallback(async (domain: string) => {
    try {
      setWellKnownStatus({ checked: false, exists: false });

      if (!domain) return;

      const wellKnownUrl = `https://${domain}/.well-known/webauthn`;

      try {
        const response = await fetch(wellKnownUrl, {
          method: 'GET',
          headers: {
            Accept: 'application/json',
          },
        });

        if (response.ok) {
          const content = await response.json();
          setWellKnownStatus({
            checked: true,
            exists: true,
            content,
          });
        } else {
          // Check if this might be an ngrok warning page
          const responseText = await response.text();
          let errorMessage = `HTTP ${response.status}: ${response.statusText}`;

          if (responseText.includes('ngrok.com') && responseText.includes('ERR_NGROK')) {
            errorMessage = `🚫 ngrok Warning Page Detected! Use: ngrok http 3000 --disable-warning-page`;
          } else if (responseText.includes('You are about to visit') && responseText.includes('ngrok')) {
            errorMessage = `🚫 ngrok Security Warning - Use --disable-warning-page flag or different tunnel service`;
          }

          setWellKnownStatus({
            checked: true,
            exists: false,
            error: errorMessage,
          });
        }
      } catch (fetchError) {
        const errorMessage = (fetchError as Error).message;
        let enhancedError = errorMessage;

        // Detect common CORS/network issues that might be ngrok-related
        if (errorMessage.includes('CORS') || errorMessage.includes('network')) {
          enhancedError = `${errorMessage} (Possible ngrok warning page - try --disable-warning-page)`;
        }

        setWellKnownStatus({
          checked: true,
          exists: false,
          error: enhancedError,
        });
      }
    } catch (error) {
      console.error('Error checking .well-known file:', error);
      setWellKnownStatus({
        checked: true,
        exists: false,
        error: (error as Error).message,
      });
    }
  }, []);

  // Load current .well-known configuration
  const loadWellKnownConfig = useCallback(async () => {
    try {
      const response = await fetch('/api/well-known/webauthn');
      if (response.ok) {
        const config = await response.json();
        setWellKnownConfig(config);
      }
    } catch (error) {
      console.error('Error loading .well-known config:', error);
    }
  }, []);

  // Add current origin to .well-known file
  const addCurrentOriginToWellKnown = async () => {
    try {
      setIsUpdatingWellKnown(true);
      const response = await fetch('/api/well-known/webauthn', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ origin: currentOrigin }),
      });

      if (response.ok) {
        const config = await response.json();
        setWellKnownConfig(config);
        await loadWellKnownConfig(); // Refresh
      } else {
        alert('Failed to add origin to .well-known file');
      }
    } catch (error) {
      console.error('Error adding origin:', error);
      alert('Error adding origin to .well-known file');
    } finally {
      setIsUpdatingWellKnown(false);
    }
  };

  // Remove current origin from .well-known file
  const removeCurrentOriginFromWellKnown = async () => {
    try {
      setIsUpdatingWellKnown(true);
      const response = await fetch('/api/well-known/webauthn', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ origin: currentOrigin }),
      });

      if (response.ok) {
        const config = await response.json();
        setWellKnownConfig(config);
        await loadWellKnownConfig(); // Refresh
      } else {
        alert('Failed to remove origin from .well-known file');
      }
    } catch (error) {
      console.error('Error removing origin:', error);
      alert('Error removing origin from .well-known file');
    } finally {
      setIsUpdatingWellKnown(false);
    }
  };

  // Create passkey with custom RP ID
  const createCrossOriginPasskey = async () => {
    if (!passkeyRpId) {
      alert('Please enter an RP ID for the passkey first');
      return;
    }

    try {
      setIsCreatingCrossOriginPasskey(true);

      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const timestamp = Date.now();
      const userId = new TextEncoder().encode(`ror-user-${timestamp}-${Math.random()}`);

      // Generate name with user input and timestamp
      const basePasskeyName = passkeyName.trim() || 'ror-demo';
      const fullPasskeyName = `${basePasskeyName}-${timestamp}`;

      // Create credential with custom RP ID using native WebAuthn API
      const credential = (await navigator.credentials.create({
        publicKey: {
          rp: {
            name: 'ROR Demo',
            id: passkeyRpId, // Use the specified RP ID (different from current origin)
          },
          user: {
            id: userId,
            name: fullPasskeyName,
            displayName: `ROR Demo User (${fullPasskeyName})`,
          },
          challenge,
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' }, // ES256
            { alg: -257, type: 'public-key' }, // RS256
          ],
          authenticatorSelection: {
            residentKey: 'preferred', // Firefox-compatible: prefer resident keys
            userVerification: 'preferred', // Firefox-compatible: prefer user verification
            // Note: No authenticatorAttachment specified for better Firefox compatibility
          },
          extensions: {
            credProps: true, // Firefox Google Password Manager compatibility
          },
          timeout: 60000,
        },
      })) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Failed to create credential');
      }

      const passkeyInfo = {
        id: credential.id,
        rpId: passkeyRpId,
        origin: currentOrigin,
        rawId: credential.rawId,
        name: fullPasskeyName,
      };

      setCrossOriginPasskeyInfo(passkeyInfo);
      setCrossOriginPasskeyCreated(true);

      // Store for later use
      localStorage.setItem('ror_passkey_info', JSON.stringify({
        id: passkeyInfo.id,
        rpId: passkeyInfo.rpId,
        origin: passkeyInfo.origin,
        name: passkeyInfo.name,
        rawId: Array.from(new Uint8Array(passkeyInfo.rawId)), // Convert for storage
      }));

      console.log('Created cross-origin passkey:', passkeyInfo);
    } catch (error) {
      console.error('Failed to create cross-origin passkey:', error);
      alert(`Failed to create passkey: ${(error as Error).message}`);
    } finally {
      setIsCreatingCrossOriginPasskey(false);
    }
  };

  // Reset passkey creation to allow new passkey
  const resetPasskeyCreation = () => {
    setCrossOriginPasskeyInfo(null);
    setCrossOriginPasskeyCreated(false);
    setCrossOriginTestResult(null);
    localStorage.removeItem('ror_passkey_info');
    console.log('Reset passkey creation - ready for new passkey');
  };

  // Test cross-origin authentication (authenticate with the passkey we just created)
  const testCrossOriginAuth = async () => {
    // If no specific passkey was created, we'll try with the RP ID from the input
    const rpIdToUse = crossOriginPasskeyInfo?.rpId || passkeyRpId;

    if (!rpIdToUse) {
      alert('Please enter an RP ID first (Step 4)');
      return;
    }

    try {
      setIsTestingCrossOrigin(true);
      setCrossOriginTestResult(null);

      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      // Try to authenticate with any passkey for the specified RP ID
      const rawCredential = (await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: rpIdToUse, // Use the RP ID from created passkey or input
          userVerification: 'preferred', // Firefox-compatible: prefer user verification
          timeout: 60000,
        },
      })) as (PublicKeyCredential & { response: AuthenticatorAssertionResponse }) | null;

      if (rawCredential) {
        // Success! The browser allowed the cross-origin request
        setCrossOriginTestResult({
          success: true,
          credentialId: rawCredential.id.slice(0, 16) + '...',
          rpId: rpIdToUse,
          origin: currentOrigin,
        });
      } else {
        setCrossOriginTestResult({
          success: false,
          error: 'No credential returned',
        });
      }
    } catch (error) {
      console.error('Cross-origin auth test failed:', error);
      setCrossOriginTestResult({
        success: false,
        error: (error as Error).message,
      });
    } finally {
      setIsTestingCrossOrigin(false);
    }
  };

  // Initialize component
  useEffect(() => {
    setMounted(true);
    if (typeof window !== 'undefined') {
      setCurrentOrigin(window.location.origin);
      // Default suggestions based on common tunnel services
      const hostname = window.location.hostname;
      if (hostname.includes('ngrok')) {
        setTargetDomainForWellKnown(hostname);
        setPasskeyRpId(hostname);
      } else if (hostname.includes('loca.lt')) {
        setTargetDomainForWellKnown(hostname);
        setPasskeyRpId(hostname);
      } else {
        setTargetDomainForWellKnown(hostname);
        setPasskeyRpId(hostname);
      }

      // Set default passkey name
      setPasskeyName('test-passkey');
    }
  }, []);

  // Check browser support on mount
  useEffect(() => {
    if (mounted) {
      void checkBrowserSupport();
      void loadWellKnownConfig();
    }
  }, [mounted, checkBrowserSupport, loadWellKnownConfig]);

  // Load stored passkey info
  useEffect(() => {
    const storedInfo = localStorage.getItem('ror_passkey_info');
    if (storedInfo) {
      try {
        const info = JSON.parse(storedInfo);
        // Convert rawId back from array
        const rawId = new Uint8Array(info.rawId).buffer;
        setCrossOriginPasskeyInfo({
          id: info.id,
          rpId: info.rpId,
          origin: info.origin,
          name: info.name || 'stored-passkey',
          rawId,
        });
        setCrossOriginPasskeyCreated(true);
        setPasskeyRpId(info.rpId);
      } catch (error) {
        console.error('Failed to parse stored passkey info:', error);
      }
    }
  }, []);

  if (!mounted) {
    return (
      <div className={styles.container}>
        <Head>
          <title>Related Origin Requests Demo</title>
          <meta content="Demo of Related Origin Requests (ROR) functionality" name="description" />
          <link href="/favicon.ico" rel="icon" />
        </Head>
        <main className={styles.main}>
          <div>Loading...</div>
        </main>
      </div>
    );
  }

  const isCurrentOriginInWellKnown = wellKnownConfig.origins.includes(currentOrigin);

  return (
    <div className={styles.container}>
      <Head>
        <title>Related Origin Requests Demo</title>
        <meta content="Demo of Related Origin Requests (ROR) functionality" name="description" />
        <link href="/favicon.ico" rel="icon" />
      </Head>

      <main className={styles.main}>
        <h1 className={styles.title}>🌐 Related Origin Requests (ROR) Demo</h1>

        <div style={{ width: '100%', maxWidth: '900px', margin: '0 auto' }}>
          {/* Step 1: Browser Support Check */}
          <div
            style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff',
            }}
          >
            <h3
              style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0',
              }}
            >
              🔍 Step 1: Browser Support Detection
            </h3>

            <div
              style={{
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #e9ecef',
              }}
            >
              <div style={{ marginBottom: '15px' }}>
                <strong>Current Origin:</strong> <code>{currentOrigin}</code>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <strong>Browser Support Status:</strong>
                <div
                  style={{
                    padding: '10px',
                    marginTop: '8px',
                    borderRadius: '4px',
                    backgroundColor:
                      browserSupportsROR === true
                        ? '#d4edda'
                        : browserSupportsROR === false
                          ? '#f8d7da'
                          : '#fff3cd',
                    border:
                      browserSupportsROR === true
                        ? '1px solid #c3e6cb'
                        : browserSupportsROR === false
                          ? '1px solid #f5c6cb'
                          : '1px solid #ffeaa7',
                    color:
                      browserSupportsROR === true
                        ? '#155724'
                        : browserSupportsROR === false
                          ? '#721c24'
                          : '#856404',
                  }}
                >
                  {browserSupportsROR === true && '✅ Supported - Your browser supports Related Origin Requests'}
                  {browserSupportsROR === false && '❌ Not Supported - Your browser does not support ROR'}
                  {browserSupportsROR === null && '⚠️ Unknown - Browser support could not be determined'}
                </div>
              </div>

              <button
                onClick={checkBrowserSupport}
                style={{
                  padding: '10px 20px',
                  backgroundColor: '#007bff',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                }}
              >
                🔄 Recheck Browser Support
              </button>
            </div>
          </div>

          {/* Step 2: Manage .well-known file */}
          <div
            style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff',
            }}
          >
            <h3
              style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0',
              }}
            >
              ⚙️ Step 2: Manage .well-known/webauthn File
            </h3>

            <div
              style={{
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #e9ecef',
              }}
            >
              <div style={{ marginBottom: '20px' }}>
                <strong>Current .well-known/webauthn configuration:</strong>
                <div
                  style={{
                    marginTop: '10px',
                    padding: '15px',
                    backgroundColor: '#ffffff',
                    border: '1px solid #dee2e6',
                    borderRadius: '4px',
                    fontFamily: 'monospace',
                    fontSize: '0.9em',
                  }}
                >
                  {wellKnownConfig.origins.length > 0 ? (
                    <pre>{JSON.stringify(wellKnownConfig, null, 2)}</pre>
                  ) : (
                    <em style={{ color: '#6c757d' }}>No origins configured</em>
                  )}
                </div>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <strong>Current Origin Status:</strong>{' '}
                <span
                  style={{
                    color: isCurrentOriginInWellKnown ? '#28a745' : '#dc3545',
                    fontWeight: 'bold',
                  }}
                >
                  {isCurrentOriginInWellKnown ? '✅ Listed in .well-known file' : '❌ Not in .well-known file'}
                </span>
              </div>

              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <button
                  onClick={addCurrentOriginToWellKnown}
                  disabled={isUpdatingWellKnown || isCurrentOriginInWellKnown}
                  style={{
                    padding: '10px 20px',
                    backgroundColor: isCurrentOriginInWellKnown || isUpdatingWellKnown ? '#6c757d' : '#28a745',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: isCurrentOriginInWellKnown || isUpdatingWellKnown ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isUpdatingWellKnown ? '🔄 Updating...' : '➕ Add Current Origin'}
                </button>

                <button
                  onClick={removeCurrentOriginFromWellKnown}
                  disabled={isUpdatingWellKnown || !isCurrentOriginInWellKnown}
                  style={{
                    padding: '10px 20px',
                    backgroundColor: !isCurrentOriginInWellKnown || isUpdatingWellKnown ? '#6c757d' : '#dc3545',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: !isCurrentOriginInWellKnown || isUpdatingWellKnown ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isUpdatingWellKnown ? '🔄 Updating...' : '🗑️ Remove Current Origin'}
                </button>

                <button
                  onClick={loadWellKnownConfig}
                  style={{
                    padding: '10px 20px',
                    backgroundColor: '#6f42c1',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer',
                  }}
                >
                  🔄 Refresh Configuration
                </button>
              </div>
            </div>
          </div>

          {/* Step 3: Configure domains and check .well-known */}
          <div
            style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff',
            }}
          >
            <h3
              style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0',
              }}
            >
              🎯 Step 3: Configure Domains for ROR
            </h3>

            <div
              style={{
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #e9ecef',
              }}
            >
              <div style={{ marginBottom: '20px' }}>
                <label style={{ fontWeight: 'bold', display: 'block', marginBottom: '5px' }}>
                  Domain to check .well-known file:
                </label>
                <input
                  type="text"
                  value={targetDomainForWellKnown}
                  onChange={(e) => setTargetDomainForWellKnown(e.target.value)}
                  placeholder="example.ngrok.io"
                  style={{
                    width: '100%',
                    padding: '10px',
                    fontFamily: 'monospace',
                    fontSize: '0.9em',
                    border: '1px solid #dee2e6',
                    borderRadius: '4px',
                    marginBottom: '10px',
                  }}
                />
                <div style={{ fontSize: '0.85em', color: '#6c757d' }}>
                  Enter the domain that should serve the .well-known/webauthn file.
                </div>
              </div>

              <button
                onClick={() => checkWellKnownFile(targetDomainForWellKnown)}
                disabled={!targetDomainForWellKnown}
                style={{
                  padding: '10px 20px',
                  backgroundColor: targetDomainForWellKnown ? '#28a745' : '#6c757d',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: targetDomainForWellKnown ? 'pointer' : 'not-allowed',
                  marginBottom: '20px',
                }}
              >
                🔍 Check .well-known/webauthn File
              </button>

              {wellKnownStatus.checked && (
                <div
                  style={{
                    padding: '15px',
                    backgroundColor: wellKnownStatus.exists ? '#d4edda' : '#f8d7da',
                    border: wellKnownStatus.exists ? '1px solid #c3e6cb' : '1px solid #f5c6cb',
                    borderRadius: '6px',
                    color: wellKnownStatus.exists ? '#155724' : '#721c24',
                  }}
                >
                  <div style={{ fontWeight: 'bold', marginBottom: '10px' }}>
                    {wellKnownStatus.exists ? '✅ .well-known file found' : '❌ .well-known file not found'}
                  </div>

                  {wellKnownStatus.exists && wellKnownStatus.content && (
                    <div>
                      <strong>Content:</strong>
                      <pre
                        style={{
                          backgroundColor: '#ffffff',
                          padding: '10px',
                          borderRadius: '4px',
                          border: '1px solid #dee2e6',
                          fontSize: '0.8em',
                          marginTop: '8px',
                          overflow: 'auto',
                        }}
                      >
                        {JSON.stringify(wellKnownStatus.content, null, 2)}
                      </pre>
                      <div style={{ marginTop: '10px', fontSize: '0.9em' }}>
                        {wellKnownStatus.content.origins?.includes(currentOrigin) ? (
                          <span style={{ color: '#155724' }}>✅ Current origin is listed - ROR should work!</span>
                        ) : (
                          <span style={{ color: '#721c24' }}>❌ Current origin is NOT listed - ROR will fail</span>
                        )}
                      </div>
                    </div>
                  )}

                  {wellKnownStatus.error && (
                    <div>
                      <strong>Error:</strong> {wellKnownStatus.error}
                    </div>
                  )}

                  <div style={{ marginTop: '10px', fontSize: '0.9em' }}>
                    <strong>Expected URL:</strong> <code>https://{targetDomainForWellKnown}/.well-known/webauthn</code>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Step 4: Create Cross-Origin Passkey */}
          <div
            style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff',
            }}
          >
            <h3
              style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0',
              }}
            >
              🔑 Step 4: Create Passkey with Cross-Origin RP ID
            </h3>

            <div
              style={{
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #e9ecef',
              }}
            >
              <div
                style={{
                  marginBottom: '20px',
                  padding: '15px',
                  backgroundColor: '#fff3cd',
                  border: '1px solid #ffeaa7',
                  borderRadius: '6px',
                  fontSize: '0.9em',
                  color: '#856404',
                }}
              >
                <strong>🎯 Key Concept:</strong> We&apos;re going to create a passkey <strong>FOR</strong> the target domain <strong>WHILE ON</strong> this domain.
                This works because the target domain&apos;s .well-known file allows this origin.
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ fontWeight: 'bold', display: 'block', marginBottom: '5px' }}>
                  Passkey Name:
                </label>
                <input
                  type="text"
                  value={passkeyName}
                  onChange={(e) => setPasskeyName(e.target.value)}
                  placeholder="my-test-passkey"
                  disabled={crossOriginPasskeyCreated}
                  style={{
                    width: '100%',
                    padding: '10px',
                    fontSize: '0.9em',
                    border: '1px solid #dee2e6',
                    borderRadius: '4px',
                    marginBottom: '10px',
                    backgroundColor: crossOriginPasskeyCreated ? '#f8f9fa' : '#ffffff',
                    color: crossOriginPasskeyCreated ? '#6c757d' : 'inherit',
                    cursor: crossOriginPasskeyCreated ? 'not-allowed' : 'text',
                  }}
                />
                <div style={{ fontSize: '0.85em', color: '#6c757d' }}>
                  {crossOriginPasskeyCreated ? (
                    <>Used for created passkey: <code>{crossOriginPasskeyInfo?.name}</code></>
                  ) : (
                    <>Final name will be: <code>{(passkeyName.trim() || 'ror-demo')}-{'{timestamp}'}</code></>
                  )}
                </div>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <label style={{ fontWeight: 'bold', display: 'block', marginBottom: '5px' }}>
                  RP ID for passkey (domain that will &quot;own&quot; this passkey):
                </label>
                <input
                  type="text"
                  value={passkeyRpId}
                  onChange={(e) => setPasskeyRpId(e.target.value)}
                  placeholder="example.ngrok.io"
                  disabled={crossOriginPasskeyCreated}
                  style={{
                    width: '100%',
                    padding: '10px',
                    fontFamily: 'monospace',
                    fontSize: '0.9em',
                    border: '1px solid #dee2e6',
                    borderRadius: '4px',
                    marginBottom: '10px',
                    backgroundColor: crossOriginPasskeyCreated ? '#f8f9fa' : '#ffffff',
                    color: crossOriginPasskeyCreated ? '#6c757d' : 'inherit',
                    cursor: crossOriginPasskeyCreated ? 'not-allowed' : 'text',
                  }}
                />
                <div style={{ fontSize: '0.85em', color: '#6c757d' }}>
                  {crossOriginPasskeyCreated ? (
                    <>Passkey created for RP ID: <code>{crossOriginPasskeyInfo?.rpId}</code></>
                  ) : (
                    <>This passkey will belong to this domain, even though we&apos;re creating it from <code>{currentOrigin}</code></>
                  )}
                </div>
              </div>

              <div style={{ marginBottom: '20px', fontSize: '0.95em', color: '#6c757d' }}>
                This will create a passkey with RP ID = <code>{passkeyRpId || 'target-domain'}</code> while on origin = <code>{currentOrigin}</code>.
                The passkey will be tied to the RP ID, not the current origin.
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '20px' }}>
                <button
                  onClick={createCrossOriginPasskey}
                  disabled={isCreatingCrossOriginPasskey || !passkeyRpId || crossOriginPasskeyCreated}
                  style={{
                    padding: '12px 24px',
                    fontSize: '0.95em',
                    backgroundColor: crossOriginPasskeyCreated
                      ? '#6c757d'
                      : !passkeyRpId
                        ? '#6c757d'
                        : '#007bff',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: crossOriginPasskeyCreated || !passkeyRpId ? 'not-allowed' : 'pointer',
                  }}
                >
                  {isCreatingCrossOriginPasskey
                    ? '🔄 Creating Cross-Origin Passkey...'
                    : crossOriginPasskeyCreated
                      ? '✅ Cross-Origin Passkey Created'
                      : '🔑 Create Cross-Origin Passkey'}
                </button>

                {crossOriginPasskeyCreated && (
                  <button
                    onClick={resetPasskeyCreation}
                    style={{
                      padding: '12px 24px',
                      fontSize: '0.95em',
                      backgroundColor: '#dc3545',
                      color: 'white',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: 'pointer',
                    }}
                  >
                    🔄 Reset & Create New
                  </button>
                )}
              </div>

              {crossOriginPasskeyCreated && (
                <div
                  style={{
                    padding: '12px',
                    backgroundColor: '#fff3cd',
                    border: '1px solid #ffeaa7',
                    borderRadius: '6px',
                    fontSize: '0.85em',
                    color: '#856404',
                    marginBottom: '20px',
                  }}
                >
                  <strong>💡 Reset Info:</strong> Click "Reset & Create New" to clear the current passkey and create a different one with new parameters.
                </div>
              )}

              {crossOriginPasskeyCreated && crossOriginPasskeyInfo && (
                <div
                  style={{
                    padding: '15px',
                    backgroundColor: '#d4edda',
                    border: '1px solid #c3e6cb',
                    borderRadius: '6px',
                    color: '#155724',
                  }}
                >
                  <div style={{ fontWeight: 'bold', marginBottom: '15px' }}>
                    ✅ Cross-Origin Passkey Created Successfully!
                  </div>

                  <div style={{ marginBottom: '10px' }}>
                    <strong>Passkey Name:</strong> <code>{crossOriginPasskeyInfo.name}</code>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <strong>Credential ID:</strong> <code>{crossOriginPasskeyInfo.id.slice(0, 32)}...</code>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <strong>RP ID (passkey owner):</strong> <code>{crossOriginPasskeyInfo.rpId}</code>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <strong>Created from Origin:</strong> <code>{crossOriginPasskeyInfo.origin}</code>
                  </div>
                  <div style={{ marginBottom: '10px' }}>
                    <strong>Full Credential ID (for sharing):</strong>
                    <div
                      style={{
                        fontFamily: 'monospace',
                        fontSize: '0.8em',
                        backgroundColor: '#ffffff',
                        padding: '8px',
                        borderRadius: '4px',
                        border: '1px solid #dee2e6',
                        wordBreak: 'break-all',
                        marginTop: '5px',
                      }}
                    >
                      {Buffer.from(crossOriginPasskeyInfo.rawId).toString('base64')}
                    </div>
                  </div>
                  <div
                    style={{
                      marginTop: '15px',
                      padding: '10px',
                      backgroundColor: '#ffffff',
                      border: '1px solid #c3e6cb',
                      borderRadius: '4px',
                      fontSize: '0.9em',
                    }}
                  >
                    <strong>✨ What just happened:</strong>
                    <br />• Created passkey &quot;{crossOriginPasskeyInfo.name}&quot; on <code>{crossOriginPasskeyInfo.origin}</code>
                    <br />• But passkey belongs to <code>{crossOriginPasskeyInfo.rpId}</code>
                    <br />• This passkey can now be used on <strong>any</strong> domain that <code>{crossOriginPasskeyInfo.rpId}</code> allows!
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Step 5: Test Cross-Origin Authentication */}
          <div
            style={{
              marginBottom: '40px',
              padding: '20px',
              border: '1px solid #e9ecef',
              borderRadius: '8px',
              backgroundColor: '#ffffff',
            }}
          >
            <h3
              style={{
                marginBottom: '20px',
                paddingBottom: '10px',
                borderBottom: '2px solid #e9ecef',
                margin: '0 0 20px 0',
              }}
            >
              🧪 Step 5: Test Cross-Origin Authentication
            </h3>

            <div
              style={{
                padding: '20px',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #e9ecef',
              }}
            >
              <div style={{ marginBottom: '20px', fontSize: '0.95em', color: '#6c757d' }}>
                {crossOriginPasskeyCreated && crossOriginPasskeyInfo ? (
                  <>
                    Test if the passkey &quot;{crossOriginPasskeyInfo.name}&quot; (created for <code>{crossOriginPasskeyInfo.rpId}</code>) can be used for authentication on this origin (<code>{currentOrigin}</code>).
                    This should work because of Related Origin Requests.
                  </>
                ) : (
                  <>
                    Test cross-origin authentication with any available passkeys for RP ID <code>{passkeyRpId || 'target-domain'}</code>.
                    This will work if you have passkeys (from Step 4, previous sessions, or other domains) that match the RP ID and if Related Origin Requests is properly configured.
                  </>
                )}
              </div>

              <button
                onClick={testCrossOriginAuth}
                disabled={isTestingCrossOrigin || !passkeyRpId}
                style={{
                  padding: '12px 24px',
                  fontSize: '0.95em',
                  backgroundColor: !passkeyRpId || isTestingCrossOrigin ? '#6c757d' : '#28a745',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: !passkeyRpId || isTestingCrossOrigin ? 'not-allowed' : 'pointer',
                  marginBottom: '20px',
                }}
              >
                {isTestingCrossOrigin
                  ? '🔄 Testing Cross-Origin Auth...'
                  : !passkeyRpId
                    ? '🔒 Enter RP ID First (Step 4)'
                    : '🧪 Test Cross-Origin Authentication'}
              </button>

              {!passkeyRpId && (
                <div
                  style={{
                    padding: '15px',
                    backgroundColor: '#fff3cd',
                    border: '1px solid #ffeaa7',
                    borderRadius: '6px',
                    color: '#856404',
                    marginBottom: '20px',
                  }}
                >
                  <div style={{ fontWeight: 'bold', marginBottom: '10px' }}>
                    ⚠️ RP ID Required
                  </div>
                  <div>
                    Enter an RP ID in Step 4 to test authentication. The test will look for any passkeys matching that RP ID.
                  </div>
                </div>
              )}

              {passkeyRpId && !crossOriginPasskeyCreated && (
                <div
                  style={{
                    padding: '15px',
                    backgroundColor: '#e7f3ff',
                    border: '1px solid #b3d9ff',
                    borderRadius: '6px',
                    color: '#004085',
                    marginBottom: '20px',
                  }}
                >
                  <div style={{ fontWeight: 'bold', marginBottom: '10px' }}>
                    🔍 Testing with Existing Passkeys
                  </div>
                  <div>
                    No passkey was created in Step 4, but the test will look for any existing passkeys with RP ID <code>{passkeyRpId}</code> (from previous sessions, other domains, etc.).
                  </div>
                </div>
              )}

              {crossOriginTestResult && (
                <div
                  style={{
                    padding: '15px',
                    backgroundColor: crossOriginTestResult.success ? '#d4edda' : '#f8d7da',
                    border: crossOriginTestResult.success ? '1px solid #c3e6cb' : '1px solid #f5c6cb',
                    borderRadius: '6px',
                    color: crossOriginTestResult.success ? '#155724' : '#721c24',
                  }}
                >
                  <div style={{ fontWeight: 'bold', marginBottom: '15px' }}>
                    {crossOriginTestResult.success
                      ? '✅ Cross-Origin Authentication Successful!'
                      : '❌ Cross-Origin Authentication Failed'}
                  </div>

                  {crossOriginTestResult.success ? (
                    <div>
                      <div>
                        <strong>Passkey Used:</strong> <code>{crossOriginPasskeyInfo?.name}</code>
                      </div>
                      <div>
                        <strong>Credential ID:</strong> <code>{crossOriginTestResult.credentialId}</code>
                      </div>
                      <div>
                        <strong>RP ID Used:</strong> <code>{crossOriginTestResult.rpId}</code>
                      </div>
                      <div>
                        <strong>Current Origin:</strong> <code>{crossOriginTestResult.origin}</code>
                      </div>
                      <div style={{ marginTop: '10px', fontSize: '0.9em' }}>
                        🎉 <strong>Related Origin Requests is working!</strong> You successfully authenticated with a passkey that belongs to <code>{crossOriginTestResult.rpId}</code> while on <code>{crossOriginTestResult.origin}</code>.
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div>
                        <strong>Error:</strong> {crossOriginTestResult.error}
                      </div>
                      <div style={{ marginTop: '10px', fontSize: '0.9em' }}>
                        This could be due to:
                        <br />• <code>{crossOriginPasskeyInfo?.rpId || passkeyRpId}</code> doesn&apos;t have a .well-known file listing <code>{currentOrigin}</code>
                        <br />• Browser doesn&apos;t support ROR
                        <br />• User cancelled the authentication prompt
                        <br />• No passkeys found for RP ID <code>{crossOriginPasskeyInfo?.rpId || passkeyRpId}</code>
                        <br />• The passkey is not available for this RP ID/origin combination
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default RelatedOriginRequestsDemo;