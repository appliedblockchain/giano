import React, { useEffect, useMemo, useState } from 'react';
import { AccountFactory__factory } from '@giano/contracts/typechain-types';
import { Button, Card, CircularProgress, Container, Divider, TextField, Typography } from '@mui/material';
import { parseAuthenticatorData } from '@simplewebauthn/server/helpers';
import { decode as cborDecode } from 'cbor-web';
import { ethers } from 'ethers';
import { getCredential } from 'services/web/src/client/common/credentials';
import { uint8ArrayToUint256 } from 'services/web/src/client/common/uint';
import type { User } from 'services/web/src/client/common/user';
import { setSessionUser } from 'services/web/src/client/common/user';
import type { CustomSnackbarProps } from 'services/web/src/client/components/CustomSnackbar';
import CustomSnackbar from 'services/web/src/client/components/CustomSnackbar';

const ES256 = -7;

const Login: React.FC = () => {
  const provider = useMemo(() => new ethers.WebSocketProvider('ws://localhost:8545'), []);
  const signer = useMemo(() => new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider), [provider]);
  const accountFactory = useMemo(() => AccountFactory__factory.connect('0x5fbdb2315678afecb367f032d93f642f64180aa3', signer), [signer]);

  const [user, setUser] = useState(null as User | null);
  const [loggingIn, setLoggingIn] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [snackbarState, setSnackbarState] = useState<CustomSnackbarProps | null>(null);
  const onSnackbarClose = () => {
    setSnackbarState((prev) => ({ ...prev, open: false }));
  };

  useEffect(() => {
    setSessionUser(user);
    if (user) {
      window.location.replace('/wallet');
    }
  }, [user]);

  const createUser = async (e) => {
    e.preventDefault();
    if (registering) {
      return;
    }
    setRegistering(true);
    const {
      username: { value: username },
    } = e.currentTarget;
    try {
      const credential = (await navigator.credentials.create({
        publicKey: {
          challenge: new TextEncoder().encode('abc'),
          authenticatorSelection: {
            requireResidentKey: true,
            residentKey: 'required',
            userVerification: 'required',
          },
          rp: {
            id: window.location.hostname,
            name: 'Giano',
          },
          user: {
            id: new TextEncoder().encode(username),
            displayName: username,
            name: username,
          },
          pubKeyCredParams: [
            {
              alg: ES256,
              type: 'public-key',
            },
          ],
          timeout: 60_000,
        },
      })) as PublicKeyCredential & { response: AuthenticatorAttestationResponse };

      const attestation = cborDecode(new Uint8Array(credential.response.attestationObject));
      const authData = parseAuthenticatorData(attestation.authData);
      const publicKey = cborDecode(authData.credentialPublicKey?.buffer as ArrayBuffer);
      const [x, y] = [publicKey.get(-2), publicKey.get(-3)];
      const userId = uint8ArrayToUint256(credential.rawId);
      await (await accountFactory.createUser(userId, { x, y })).wait();
      setSnackbarState({ severity: 'success', message: 'Passkey account created successfully.', open: true });
    } catch (e) {
      setSnackbarState({ severity: 'error', message: 'Something went wrong. Please check the console', open: true });
      console.error(e);
    } finally {
      setRegistering(false);
    }
  };

  const logIn = async (e) => {
    e.preventDefault();
    if (loggingIn) {
      return;
    }
    setLoggingIn(true);
    try {
      const credential = await getCredential();
      const userId = uint8ArrayToUint256(credential.rawId);
      if (credential) {
        const user = await accountFactory.getUser(userId);
        if (user.account !== ethers.ZeroAddress) {
          setUser({
            account: user.account,
            rawId: new Uint8Array(credential.rawId),
            credentialId: userId.toString(),
          });
        }
      }
    } catch (e) {
      console.error(e);
      setSnackbarState({ severity: 'error', open: true, message: 'Something went wrong. Please check the console' });
    } finally {
      setLoggingIn(false);
    }
  };

  return (
    <Container
      sx={{
        width: '100vw',
        height: '100vh',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
      }}
    >
      <Card
        sx={{
          width: '500px',
          height: '660px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          padding: '30px',
          gap: '30px',
        }}
      >
        <img alt="Giano logo" src="/logo.svg" />
        <form onSubmit={logIn}>
          <Button
            type="submit"
            disabled={loggingIn}
            variant="contained"
            sx={{
              '&.Mui-disabled': { backgroundColor: 'primary.dark' },
            }}
          >
            {loggingIn ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Login'}
          </Button>
        </form>
        <Divider flexItem>
          <Typography>or</Typography>
        </Divider>
        <form onSubmit={createUser} style={{ display: 'flex', flexDirection: 'column', textAlign: 'center', width: '100%', gap: 'inherit' }}>
          <Typography variant="h4">Create account</Typography>
          <TextField name="username" label="Passkey" required />
          <Button
            type="submit"
            disabled={registering}
            variant="contained"
            sx={{
              '&.Mui-disabled': { backgroundColor: 'primary.dark' },
            }}
          >
            {registering ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Create account'}
          </Button>
        </form>
        <CustomSnackbar {...snackbarState} onClose={onSnackbarClose} />
      </Card>
    </Container>
  );
};

export default Login;
