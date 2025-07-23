import type { NextPage } from 'next';
import Head from 'next/head';
import React, { useEffect, useState } from 'react';
import { createWebAuthnCredential } from 'viem/account-abstraction';

interface TestConfig {
  name: string;
  description: string;
  authenticatorSelection: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    requireResidentKey?: boolean;
    residentKey?: 'required' | 'preferred' | 'discouraged';
    userVerification?: 'required' | 'preferred' | 'discouraged';
  };
  timeout?: number;
}

const testConfigurations: TestConfig[] = [
  {
    name: 'Current Default',
    description: 'Platform, resident key required, UV required',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      userVerification: 'required',
      residentKey: 'required',
    },
  },
  {
    name: 'Minimal Platform',
    description: 'Platform only, no other constraints',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
    },
  },
  {
    name: 'Platform + UV Preferred',
    description: 'Platform, user verification preferred',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'preferred',
    },
  },
  {
    name: 'Platform + UV Discouraged',
    description: 'Platform, user verification discouraged',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'discouraged',
    },
  },
  {
    name: 'Platform + RK Preferred',
    description: 'Platform, resident key preferred',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  },
  {
    name: 'Platform + RK Discouraged',
    description: 'Platform, resident key discouraged',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'discouraged',
      userVerification: 'preferred',
    },
  },
  {
    name: 'Any Authenticator',
    description: 'No authenticator attachment specified',
    authenticatorSelection: {
      userVerification: 'preferred',
      residentKey: 'preferred',
    },
  },
  {
    name: 'Cross-Platform',
    description: 'Cross-platform authenticators only',
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      userVerification: 'required',
    },
  },
  {
    name: 'Legacy Boolean RK',
    description: 'Legacy requireResidentKey: false',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: false,
      userVerification: 'preferred',
    },
  },
  {
    name: 'Short Timeout',
    description: 'Platform with 15s timeout',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'preferred',
    },
    timeout: 15000,
  },
  {
    name: 'Long Timeout',
    description: 'Platform with 120s timeout',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'preferred',
    },
    timeout: 120000,
  },
  {
    name: 'Conservative',
    description: 'Most compatible options for Android',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'discouraged',
      residentKey: 'discouraged',
    },
    timeout: 30000,
  },
];

const AndroidPasskeyTest: NextPage = () => {
  const [mounted, setMounted] = useState(false);
  const [isCreating, setIsCreating] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, { success: boolean; data: string; timestamp: number }>>({});

  // Effect to handle hydration
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  const createPasskeyWithConfig = async (config: TestConfig) => {
    const configKey = config.name;
    setIsCreating(configKey);
    
    // Clear previous result for this config
    setResults(prev => {
      const newResults = { ...prev };
      delete newResults[configKey];
      return newResults;
    });

    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const userId = new TextEncoder().encode(`android-test-${Date.now()}-${Math.random()}`);

      console.log('Creating WebAuthn credential with config:', config);

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
        authenticatorSelection: config.authenticatorSelection,
        timeout: config.timeout || 60000,
      });

      const successMessage = `✅ SUCCESS - ${config.name}
Configuration: ${config.description}
ID: ${credential.id}
Raw ID Length: ${credential.raw.rawId.byteLength} bytes
Type: ${(credential as any).type || 'unknown'}
Authenticator Attachment: ${credential.raw.authenticatorAttachment || 'not specified'}
Client Data JSON: ${credential.raw.response.clientDataJSON ? 'present' : 'missing'}
Attestation Object: ${(credential.raw.response as any).attestationObject ? 'present' : 'missing'}
Timeout Used: ${config.timeout || 60000}ms

Full Config:
${JSON.stringify(config.authenticatorSelection, null, 2)}`;

      setResults(prev => ({
        ...prev,
        [configKey]: {
          success: true,
          data: successMessage,
          timestamp: Date.now(),
        }
      }));

      console.log('Credential created successfully:', credential);
    } catch (err: any) {
      const errorMessage = `❌ FAILED - ${config.name}
Configuration: ${config.description}
Error Name: ${err.name || 'Unknown'}
Error Message: ${err.message || 'No message provided'}
Error Code: ${err.code || 'No code provided'}
Timeout Used: ${config.timeout || 60000}ms

Full Config:
${JSON.stringify(config.authenticatorSelection, null, 2)}

User Agent: ${navigator.userAgent}
Platform: ${navigator.platform || 'Unknown'}
WebAuthn Support: ${window.PublicKeyCredential ? 'Yes' : 'No'}

Stack Trace: ${err.stack || 'No stack trace available'}
Full Error: ${JSON.stringify(err, null, 2)}`;

      setResults(prev => ({
        ...prev,
        [configKey]: {
          success: false,
          data: errorMessage,
          timestamp: Date.now(),
        }
      }));

      console.error('Failed to create passkey:', err);
    } finally {
      setIsCreating(null);
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

  const clearResults = () => {
    setResults({});
  };

  const clearResult = (configName: string) => {
    setResults(prev => {
      const newResults = { ...prev };
      delete newResults[configName];
      return newResults;
    });
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
        <meta name="description" content="Android passkey compatibility test with multiple configurations" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link rel="icon" href="/favicon.ico" />
        <style jsx>{`
          @media (min-width: 640px) {
            .result-header {
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
          maxWidth: '1200px',
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
          Android Passkey Compatibility Test
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
          Test different AuthenticatorSelectionCriteria combinations for Android 14+ compatibility
        </p>

        {/* Clear Results Button */}
        <div style={{ margin: '1rem 0', textAlign: 'center' }}>
          <button
            onClick={clearResults}
            style={{
              padding: '0.5rem 1rem',
              fontSize: '0.9rem',
              backgroundColor: '#dc3545',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              marginBottom: '1rem',
            }}
          >
            Clear All Results
          </button>
        </div>

        {/* Test Configuration Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '1rem',
            width: '100%',
            marginBottom: '2rem',
          }}
        >
          {testConfigurations.map((config) => (
            <div
              key={config.name}
              style={{
                border: '1px solid #ccc',
                borderRadius: '8px',
                padding: '1rem',
                backgroundColor: '#f9f9f9',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem',
              }}
            >
              <h3 style={{ margin: '0', fontSize: '1.1rem', color: '#333' }}>
                {config.name}
              </h3>
              <p style={{ margin: '0', fontSize: '0.9rem', color: '#666', lineHeight: '1.4' }}>
                {config.description}
              </p>
              <details style={{ fontSize: '0.8rem', color: '#777' }}>
                <summary style={{ cursor: 'pointer', marginBottom: '0.5rem' }}>
                  View Configuration
                </summary>
                <pre style={{ 
                  fontSize: '0.75rem', 
                  backgroundColor: '#f0f0f0', 
                  padding: '0.5rem', 
                  borderRadius: '4px',
                  overflow: 'auto',
                  margin: '0',
                }}>
                  {JSON.stringify(config.authenticatorSelection, null, 2)}
                  {config.timeout && `\ntimeout: ${config.timeout}ms`}
                </pre>
              </details>
              <button
                onClick={() => createPasskeyWithConfig(config)}
                disabled={isCreating === config.name}
                style={{
                  padding: '0.75rem 1rem',
                  fontSize: '0.9rem',
                  backgroundColor: isCreating === config.name ? '#ccc' : '#0070f3',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: isCreating === config.name ? 'not-allowed' : 'pointer',
                  minHeight: '44px',
                }}
              >
                {isCreating === config.name ? 'Testing...' : 'Test Configuration'}
              </button>
            </div>
          ))}
        </div>

        {/* Results Section */}
        {Object.keys(results).length > 0 && (
          <div style={{ width: '100%' }}>
            <h2 style={{ fontSize: '1.5rem', marginBottom: '1rem', color: '#333' }}>
              Test Results
            </h2>
            {Object.entries(results)
              .sort(([,a], [,b]) => b.timestamp - a.timestamp)
              .map(([configName, result]) => (
                <div
                  key={configName}
                  style={{
                    margin: '1rem 0',
                    padding: '1rem',
                    backgroundColor: result.success ? '#d4edda' : '#f8d7da',
                    border: `1px solid ${result.success ? '#c3e6cb' : '#f5c6cb'}`,
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
                    className="result-header"
                  >
                    <strong style={{ 
                      color: result.success ? '#155724' : '#721c24', 
                      fontSize: 'clamp(0.9rem, 3vw, 1.1rem)' 
                    }}>
                      {result.success ? '✅' : '❌'} {configName} - {new Date(result.timestamp).toLocaleTimeString()}
                    </strong>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        onClick={() => copyToClipboard(result.data)}
                        style={{
                          padding: '0.5rem 1rem',
                          fontSize: 'clamp(0.8rem, 2.5vw, 0.85rem)',
                          backgroundColor: result.success ? '#28a745' : '#dc3545',
                          color: 'white',
                          border: 'none',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          minHeight: '36px',
                        }}
                      >
                        Copy
                      </button>
                      <button
                        onClick={() => clearResult(configName)}
                        style={{
                          padding: '0.5rem 1rem',
                          fontSize: 'clamp(0.8rem, 2.5vw, 0.85rem)',
                          backgroundColor: '#6c757d',
                          color: 'white',
                          border: 'none',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          minHeight: '36px',
                        }}
                      >
                        Clear
                      </button>
                    </div>
                  </div>
                  <div style={{ 
                    color: result.success ? '#155724' : '#721c24', 
                    lineHeight: '1.4' 
                  }}>
                    {result.data}
                  </div>
                </div>
              ))}
          </div>
        )}

        {/* Environment Info */}
        <div
          style={{
            margin: '2rem 0 1rem 0',
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
            width: '100%',
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
          window.PublicKeyCredential: {typeof window !== 'undefined' && window.PublicKeyCredential ? 'Available ✅' : 'Missing ❌'}
          <br />
          navigator.credentials: {typeof navigator !== 'undefined' && navigator.credentials ? 'Available ✅' : 'Missing ❌'}
          <br />
          navigator.credentials.create: {typeof navigator !== 'undefined' && navigator.credentials && typeof navigator.credentials.create === 'function' ? 'Available ✅' : 'Missing ❌'}
          <br />
          navigator.credentials.get: {typeof navigator !== 'undefined' && navigator.credentials && typeof navigator.credentials.get === 'function' ? 'Available ✅' : 'Missing ❌'}
          <br />
          PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable: {typeof window !== 'undefined' && window.PublicKeyCredential && typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function' ? 'Available ✅' : 'Missing ❌'}
          <br />
          <br />
          <strong style={{ fontSize: 'clamp(0.8rem, 2.5vw, 1rem)' }}>Browser Info:</strong>
          <br />
          Is Secure Context (HTTPS): {typeof window !== 'undefined' && window.isSecureContext ? 'Yes ✅' : 'No ❌'}
          <br />
          Is Cross-Origin Isolated: {typeof window !== 'undefined' && window.crossOriginIsolated ? 'Yes ✅' : 'No ❌'}
        </div>

        {/* Usage Instructions */}
        <div
          style={{
            margin: '1rem 0',
            padding: '1rem',
            backgroundColor: '#fff3cd',
            border: '1px solid #ffeaa7',
            borderRadius: '8px',
            fontSize: 'clamp(0.8rem, 2.5vw, 0.9rem)',
            lineHeight: '1.5',
            width: '100%',
          }}
        >
          <h3 style={{ margin: '0 0 1rem 0', color: '#856404' }}>🔍 Testing Strategy for Android 14+</h3>
          <ul style={{ margin: '0', paddingLeft: '1.5rem', color: '#856404' }}>
            <li><strong>Start with "Conservative"</strong> - Most likely to work on problematic devices</li>
            <li><strong>Try "Minimal Platform"</strong> - Reduces constraints to bare minimum</li>
            <li><strong>Test "Platform + UV Discouraged"</strong> - Some Android versions have UV issues</li>
            <li><strong>Compare timeouts</strong> - Android might need more time</li>
            <li><strong>Check legacy options</strong> - Some browsers prefer old requireResidentKey boolean</li>
          </ul>
          <p style={{ margin: '1rem 0 0 0', color: '#856404' }}>
            💡 <strong>Tip:</strong> If a configuration works, copy the result and use those exact settings in your production code.
          </p>
        </div>
      </main>
    </div>
  );
};

export default AndroidPasskeyTest; 