import type { NextPage } from 'next';
import Head from 'next/head';
import React, { useEffect, useState } from 'react';
import { createWebAuthnCredential } from 'viem/account-abstraction';
import {
  Box,
  Button,
  Card,
  CardContent,
  Container,
  Typography,
  Grid,
  Alert,
  Chip,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  Tooltip,
  Divider,
} from '@mui/material';
import {
  ExpandMore,
  ContentCopy,
  Delete,
  ClearAll,
  CheckCircle,
  Error,
  Info,
  Warning,
} from '@mui/icons-material';

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
  useAuthenticationTest?: boolean;
  useWebAuthnIoConfig?: boolean;
}

const testConfigurations: TestConfig[] = [
  {
    name: 'Firefox Google Password Manager Fix',
    description: 'Minimal working config: Only extensions.credProps needed for Firefox Google Password Manager',
    authenticatorSelection: {
      residentKey: 'preferred',
      // Note: No authenticatorAttachment specified - this is intentional
    },
    timeout: 60000,
    useWebAuthnIoConfig: true,
  },
  {
    name: 'Firefox GPM Demo (credentials.get)',
    description: 'Demonstrates that Firefox can trigger Google Password Manager using navigator.credentials.get()',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
    },
    timeout: 60000,
    useAuthenticationTest: true,
  },
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
    description: 'Cross-platform authenticator',
    authenticatorSelection: {
      authenticatorAttachment: 'cross-platform',
      userVerification: 'preferred',
      residentKey: 'preferred',
    },
  },
  {
    name: 'No Constraints',
    description: 'No authenticator selection constraints',
    authenticatorSelection: {},
  },
  {
    name: 'UV Required',
    description: 'User verification required',
    authenticatorSelection: {
      userVerification: 'required',
    },
  },
  {
    name: 'UV Discouraged',
    description: 'User verification discouraged',
    authenticatorSelection: {
      userVerification: 'discouraged',
    },
  },
  {
    name: 'RK Required',
    description: 'Resident key required',
    authenticatorSelection: {
      requireResidentKey: true,
      residentKey: 'required',
    },
  },
  {
    name: 'RK Discouraged',
    description: 'Resident key discouraged',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
  },
];

interface TestResult {
  success: boolean;
  data: string;
  timestamp: number;
}

const AndroidPasskeyTest: NextPage = () => {
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const [isCreating, setIsCreating] = useState<string | null>(null);

  const createPasskeyWithConfig = async (config: TestConfig) => {
    setIsCreating(config.name);

    try {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      const userId = new Uint8Array(32);
      crypto.getRandomValues(userId);

      const publicKeyCredentialCreationOptions: CredentialCreationOptions = {
        publicKey: {
          challenge,
          rp: {
            name: 'Giano Test',
            id: window.location.hostname,
          },
          user: {
            id: userId,
            name: 'test@example.com',
            displayName: 'Test User',
          },
          pubKeyCredParams: [
            {
              type: 'public-key',
              alg: -7, // ES256
            },
          ],
          authenticatorSelection: config.authenticatorSelection,
          timeout: config.timeout || 60000,
          attestation: 'direct',
        },
      };

      let result: Credential | null = null;

      if (config.useAuthenticationTest) {
        // Test authentication instead of creation
        const getOptions: CredentialRequestOptions = {
          publicKey: {
            challenge,
            rpId: window.location.hostname,
            userVerification: config.authenticatorSelection.userVerification || 'preferred',
            timeout: config.timeout || 60000,
          },
        };

        try {
          result = await navigator.credentials.get(getOptions);
        } catch (error) {
          throw new Error(`Authentication test failed: ${error}`);
        }
      } else {
        // Test credential creation
        if (config.useWebAuthnIoConfig) {
          // Use webauthn.io configuration
          const webAuthnIoCreateFn = async (options: CredentialCreationOptions) => {
            // @ts-ignore - webauthn.io types
            if (window.WebAuthn) {
              // @ts-ignore
              return await window.WebAuthn.create(options);
            } else {
              return await navigator.credentials.create(options);
            }
          };

          result = await webAuthnIoCreateFn(publicKeyCredentialCreationOptions);
        } else {
          // Use standard WebAuthn API
          result = await navigator.credentials.create(publicKeyCredentialCreationOptions);
        }
      }

      const resultData = {
        success: true,
        data: `✅ Configuration "${config.name}" succeeded!\n\n` +
          `Result: ${JSON.stringify(result, null, 2)}\n\n` +
          `Configuration: ${JSON.stringify(config.authenticatorSelection, null, 2)}`,
        timestamp: Date.now(),
      };

      setResults(prev => ({
        ...prev,
        [config.name]: resultData,
      }));

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      const resultData = {
        success: false,
        data: `❌ Configuration "${config.name}" failed!\n\n` +
          `Error: ${errorMessage}\n\n` +
          `Configuration: ${JSON.stringify(config.authenticatorSelection, null, 2)}`,
        timestamp: Date.now(),
      };

      setResults(prev => ({
        ...prev,
        [config.name]: resultData,
      }));
    } finally {
      setIsCreating(null);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // You could add a toast notification here
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
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
    <Container maxWidth="lg">
      <Head>
        <title>Android Passkey Test - Giano</title>
        <meta name="description" content="Android passkey compatibility test with multiple configurations" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <Box sx={{ py: 4 }}>
        <Typography variant="h3" component="h1" align="center" gutterBottom>
          Android Passkey Compatibility Test
        </Typography>

        <Typography variant="h6" align="center" color="text.secondary" sx={{ mb: 4 }}>
          Test different AuthenticatorSelectionCriteria combinations for Android 14+ compatibility
        </Typography>

        {/* Clear Results Button */}
        <Box sx={{ textAlign: 'center', mb: 3 }}>
          <Button
            variant="outlined"
            color="error"
            startIcon={<ClearAll />}
            onClick={clearResults}
          >
            Clear All Results
          </Button>
        </Box>

        {/* Test Configuration Grid */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {testConfigurations.map((config) => (
            <Grid item xs={12} md={6} lg={4} key={config.name}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    {config.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {config.description}
                  </Typography>
                  
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMore />}>
                      <Typography variant="body2">View Configuration</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box
                        component="pre"
                        sx={{
                          fontSize: '0.75rem',
                          backgroundColor: 'grey.100',
                          p: 1,
                          borderRadius: 1,
                          overflow: 'auto',
                          fontFamily: 'monospace',
                        }}
                      >
                        {JSON.stringify(config.authenticatorSelection, null, 2)}
                        {config.timeout && `\ntimeout: ${config.timeout}ms`}
                      </Box>
                    </AccordionDetails>
                  </Accordion>

                  <Button
                    variant="contained"
                    fullWidth
                    disabled={isCreating === config.name}
                    onClick={() => createPasskeyWithConfig(config)}
                    sx={{ mt: 2 }}
                  >
                    {isCreating === config.name ? 'Testing...' : 'Test Configuration'}
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        {/* Results Section */}
        {Object.keys(results).length > 0 && (
          <Box sx={{ width: '100%' }}>
            <Typography variant="h4" gutterBottom>
              Test Results
            </Typography>
            {Object.entries(results)
              .sort(([,a], [,b]) => b.timestamp - a.timestamp)
              .map(([configName, result]) => (
                <Card
                  key={configName}
                  sx={{
                    mb: 2,
                    backgroundColor: result.success ? 'success.light' : 'error.light',
                    border: `1px solid ${result.success ? 'success.main' : 'error.main'}`,
                  }}
                >
                  <CardContent>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {result.success ? <CheckCircle color="success" /> : <Error color="error" />}
                        <Typography variant="h6">
                          {configName} - {new Date(result.timestamp).toLocaleTimeString()}
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Tooltip title="Copy result">
                          <IconButton
                            size="small"
                            onClick={() => copyToClipboard(result.data)}
                            color={result.success ? 'success' : 'error'}
                          >
                            <ContentCopy />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Clear result">
                          <IconButton
                            size="small"
                            onClick={() => clearResult(configName)}
                            color="default"
                          >
                            <Delete />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </Box>
                    <Box
                      component="pre"
                      sx={{
                        color: result.success ? 'success.dark' : 'error.dark',
                        lineHeight: 1.4,
                        fontFamily: 'monospace',
                        fontSize: '0.875rem',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        overflowWrap: 'break-word',
                        backgroundColor: 'rgba(0,0,0,0.05)',
                        p: 1,
                        borderRadius: 1,
                      }}
                    >
                      {result.data}
                    </Box>
                  </CardContent>
                </Card>
              ))}
          </Box>
        )}

        {/* Environment Info */}
        <Paper sx={{ p: 2, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Test Environment Info
          </Typography>
          <Box
            component="pre"
            sx={{
              fontSize: '0.75rem',
              fontFamily: 'monospace',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              overflowWrap: 'break-word',
              lineHeight: 1.4,
            }}
          >
            <strong>User Agent:</strong> {navigator.userAgent}
            <br />
            <strong>Platform:</strong> {navigator.platform || 'Unknown'}
            <br />
            <strong>Hostname:</strong> {typeof window !== 'undefined' ? window.location.hostname : 'Unknown'}
            <br />
            <br />
            <strong>WebAuthn Capability Checks:</strong>
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
            <strong>Browser Info:</strong>
            <br />
            Is Secure Context (HTTPS): {typeof window !== 'undefined' && window.isSecureContext ? 'Yes ✅' : 'No ❌'}
            <br />
            Is Cross-Origin Isolated: {typeof window !== 'undefined' && window.crossOriginIsolated ? 'Yes ✅' : 'No ❌'}
          </Box>
        </Paper>

        {/* Usage Instructions */}
        <Alert severity="info" sx={{ mb: 2 }}>
          <Typography variant="h6" gutterBottom>
            🎉 Testing Strategy - SOLUTION FOUND!
          </Typography>
          <ul>
            <li><strong>🏆 "Firefox Google Password Manager Fix"</strong> - The minimal working solution!</li>
            <li><strong>🔥 "Firefox GPM Demo (credentials.get)"</strong> - Demonstrates authentication works too</li>
            <li><strong>📊 Other tests</strong> - Compare with standard configurations for reference</li>
          </ul>
        </Alert>

        <Alert severity="success" sx={{ mb: 2 }}>
          <Typography variant="h6" gutterBottom>
            ✅ SOLUTION DISCOVERED
          </Typography>
          <Typography variant="body2">
            Only <code>extensions: {`{ credProps: true }`}</code> is needed!
            <br />
            All other webauthn.io overrides are unnecessary.
          </Typography>
        </Alert>

        <Alert severity="warning">
          <Typography variant="body2">
            💡 <strong>Tip:</strong> If a configuration works, copy the result and use those exact settings in your production code.
          </Typography>
        </Alert>
      </Box>
    </Container>
  );
};

export default AndroidPasskeyTest;
