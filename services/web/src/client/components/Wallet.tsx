import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type { GenericERC20, GenericERC721 } from '@giano/contracts/typechain-types';
import { GenericERC20__factory, GenericERC721__factory } from '@giano/contracts/typechain-types';
import { Logout } from '@mui/icons-material';
import { Box, Button, Card, CircularProgress, Container, FormControl, MenuItem, Select, Tab, Tabs, TextField, Typography } from '@mui/material';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { ethers } from 'ethers';
import { getCredential } from 'services/web/src/client/common/credentials';
import type { ProxiedContract } from 'services/web/src/client/common/gianoWalletClient';
import { GianoWalletClient } from 'services/web/src/client/common/gianoWalletClient';
import { hexToUint8Array, uint8ArrayToUint256 } from 'services/web/src/client/common/uint';
import type { User } from 'services/web/src/client/common/user';
import { getSessionUser } from 'services/web/src/client/common/user';
import type { CustomSnackbarProps } from 'services/web/src/client/components/CustomSnackbar';
import CustomSnackbar from 'services/web/src/client/components/CustomSnackbar';
import { Copy } from '../icons';

type TransferFormValues = {
  recipient: string;
  tokenId: string;
};

type TransferFormProps = {
  tokenProxy?: ProxiedContract<GenericERC721>;
  user?: User;
  formValues: TransferFormValues;
  onSuccess: () => void;
  onFailure: (message?: string) => void;
  onChange: (event: React.SyntheticEvent) => void;
};

const faucetDropAmount = ethers.parseEther('100');

type TabPanelProps = {
  children?: React.ReactNode;
  title: string;
  index: number;
  tab: number;
  [other: string]: any;
};

const TabPanel: React.FC<TabPanelProps> = ({ children, tab, index, title, ...other }: TabPanelProps) => {
  return (
    <div role="tabpanel" style={{ width: '100%', height: '100%', paddingTop: '1em' }} hidden={tab !== index} id={`tab-${index}`} {...other}>
      <Box>
        <Typography variant="h4" color="primary" align="center">
          {title}
        </Typography>
      </Box>
      <Box display="flex" flexDirection="column" justifyContent="space-around" height="100%">
        {tab === index && children}
      </Box>
    </div>
  );
};

const TransferForm = ({ user, onSuccess, onFailure, tokenProxy, formValues, onChange }: TransferFormProps) => {
  const [transferring, setTransferring] = useState(false);
  const transfer = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setTransferring(true);
    try {
      if (tokenProxy && user) {
        const { recipient, tokenId } = formValues;
        const tx = await tokenProxy.transferFrom(user.account, recipient, tokenId).send();
        await tx.wait();
        onSuccess();
      }
    } catch (e) {
      const err = e as Error;
      console.error(err);
      onFailure(err.message);
    } finally {
      setTransferring(false);
    }
  };
  return (
    <form style={{ display: 'flex', flexDirection: 'column', gap: 20 }} onSubmit={transfer}>
      <TextField
        name="recipient"
        value={formValues.recipient}
        onChange={onChange}
        label="Recipient address"
        variant="standard"
        required
        disabled={transferring}
      />
      <TextField name="tokenId" value={formValues.tokenId} label="Token ID" type="number" onChange={onChange} required disabled={transferring} />
      <SubmitButtonWithProgress running={transferring} label="Transfer token" />
    </form>
  );
};

type SendCoinsFormValues = {
  recipient: string;
  amount: string;
};

type SendCoinsFormProps = {
  user?: User;
  coinContractProxy?: ProxiedContract<GenericERC20>;
  values: SendCoinsFormValues;
  onSuccess: () => void;
  onFailure: (message?: string) => void;
  onChange: (e: React.SyntheticEvent) => void;
};

const SendCoinsForm: React.FC<SendCoinsFormProps> = ({ user, onSuccess, onFailure, coinContractProxy, values, onChange }) => {
  const [sending, setSending] = useState(false);

  const send = async (e: React.FormEvent<HTMLFormElement>) => {
    try {
      if (user && coinContractProxy) {
        e.preventDefault();
        setSending(true);
        const tx = await coinContractProxy.transfer(values.recipient, ethers.parseEther(values.amount)).send();
        await tx.wait();
        onSuccess();
      }
    } catch (e) {
      const err = e as Error;
      console.error(e);
      onFailure(err.message);
    } finally {
      setSending(false);
    }
  };
  return (
    <form style={{ display: 'flex', flexDirection: 'column', gap: 20 }} onSubmit={send}>
      <TextField value={values.recipient} onChange={onChange} name="recipient" label="Recipient address" variant="standard" required disabled={sending} />
      <TextField value={values.amount} onChange={onChange} name="amount" label="Amount" type="number" required disabled={sending} />
      <SubmitButtonWithProgress label="Send" running={sending} />
    </form>
  );
};

type SubmitButtonWithProgressProps = {
  label: string;
  running: boolean;
  sx?: any;
};

const SubmitButtonWithProgress: React.FC<SubmitButtonWithProgressProps> = ({ running, label, sx }) => {
  return (
    <Button
      type="submit"
      disabled={running}
      variant="contained"
      sx={{
        '&.Mui-disabled': { backgroundColor: 'primary.dark' },
        width: '100%',
        ...sx,
      }}
    >
      {running ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : label}
    </Button>
  );
};

function getChallengeSigner(user: User) {
  return async (challengeHex: string) => {
    const challenge = hexToUint8Array(challengeHex);

    const credential = await getCredential(user.rawId, challenge);

    const parsedSignature = AsnParser.parse(credential.response.signature, ECDSASigValue);

    const clientDataJson = new TextDecoder().decode(credential.response.clientDataJSON);
    const responseTypeLocation = clientDataJson.indexOf('"type":');
    const challengeLocation = clientDataJson.indexOf('"challenge":');
    return ethers.AbiCoder.defaultAbiCoder().encode(
      ['tuple(bytes authenticatorData, string clientDataJSON, uint256 challengeLocation, uint256 responseTypeLocation, uint256 r, uint256 s)'],
      [
        [
          new Uint8Array(credential.response.authenticatorData),
          clientDataJson,
          challengeLocation,
          responseTypeLocation,
          uint8ArrayToUint256(parsedSignature.r),
          uint8ArrayToUint256(parsedSignature.s),
        ],
      ],
    );
  };
}

const Wallet: React.FC = () => {
  const [tab, setTab] = useState(0);
  const [minting, setMinting] = useState(false);
  const [tokenId, setTokenId] = useState('');
  const [user, setUser] = useState<User | undefined>(undefined);
  const [snackbarState, setSnackbarState] = useState<CustomSnackbarProps | null>(null);
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [faucetRunning, setFaucetRunning] = useState(false);
  const [transferFormValues, setTransferFormValues] = useState<TransferFormValues>({ recipient: '', tokenId: '' });
  const [sendCoinsFormValues, setSendCoinsFormValues] = useState<SendCoinsFormValues>({ recipient: '', amount: '' });

  const provider = useMemo(() => new ethers.WebSocketProvider('ws://localhost:8545'), []);
  const signer = useMemo(() => new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider), [provider]);
  const walletClient = useMemo(
    () =>
      user && signer
        ? GianoWalletClient({
            address: user.account,
            signer: signer,
            challengeSigner: getChallengeSigner(user),
          })
        : undefined,
    [user, signer],
  );
  const tokenContract = useMemo(() => GenericERC721__factory.connect('0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0', signer), [signer]);
  const coinContract = useMemo(() => GenericERC20__factory.connect('0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', signer), [signer]);
  const tokenProxy = useMemo(() => (walletClient ? walletClient.proxyFor(tokenContract) : undefined), [tokenContract, walletClient]);
  const coinProxy = useMemo(() => (walletClient ? walletClient.proxyFor(coinContract) : undefined), [coinContract, walletClient]);

  const handleFormChange = (setter: React.SetStateAction<any>) => (event) => {
    const { name, value } = event.target;
    setter((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const updateBalance = async () => {
    if (user) {
      const balance = await coinContract.balanceOf(user.account);
      setWalletBalance(ethers.formatEther(balance));
    }
  };

  useEffect(() => {
    // Typechain-generated event listener is not working
    const ethersContract = new ethers.Contract(coinContract.target, coinContract.interface, provider);
    if (walletBalance === null && user) {
      void updateBalance();
    }
    const listener = async (from, to) => {
      if (user && [from, to].map((a) => a.toLowerCase()).includes(user.account.toLowerCase())) {
        await updateBalance();
      }
    };
    void ethersContract.on('Transfer', listener);
    return () => {
      void ethersContract.off('Transfer', listener);
    };
  }, [coinContract, user]);

  const handleTabChange = useCallback((_event: React.SyntheticEvent, newTab: number) => {
    setTab(newTab);
  }, []);

  const onSnackbarClose = () => {
    setSnackbarState((prev) => ({ ...prev, open: false }));
  };

  useEffect(() => {
    const user = getSessionUser();
    if (!user) {
      window.location.replace('/');
      return;
    }
    setUser(user);
  }, []);

  const mint = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (!minting && user) {
      try {
        setMinting(true);
        const tx = await tokenContract.mint(user.account);
        const receipt = await tx.wait();
        if (receipt) {
          const transfer = tokenContract.interface.parseLog(receipt.logs[0]);
          if (transfer) {
            const [, , tokenId] = transfer.args;
            setTokenId(tokenId.toString());
          }
        }
      } finally {
        setMinting(false);
      }
    }
  };

  const transferFromFaucet = async (e) => {
    e.preventDefault();
    if (user) {
      setFaucetRunning(true);
      try {
        const tx = await coinContract.transfer(user.account, faucetDropAmount);
        await tx.wait();
      } finally {
        setFaucetRunning(false);
      }
    }
  };

  const copyTokenId = async () => {
    await window.navigator.clipboard.writeText(tokenId);
  };

  const writeAccountToClipboard = async () => {
    if (user?.account) {
      await window.navigator.clipboard.writeText(user.account);
      setSnackbarState({ open: true, severity: 'success', message: 'Account address copied to clipboard' });
    }
  };

  const logout = () => {
    setUser(undefined);
    window.location.href = '/';
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
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Box display="flex" justifyContent="space-between" width="100%">
          <img alt="Giano logo" src="/logo_horizontal.svg" />
          <FormControl sx={{ width: '50%' }}>
            <Select labelId="account-select-label" value="account">
              <MenuItem onClick={writeAccountToClipboard} value="account">
                {user?.account}
              </MenuItem>
              <MenuItem onClick={logout}>
                <Logout />
                Log Out
              </MenuItem>
            </Select>
          </FormControl>
        </Box>
        <Card sx={{ backgroundColor: 'grey.100', width: '100%', textAlign: 'center', p: '16 40 16 40' }}>
          <Typography color="primary">Available</Typography>
          <Typography variant="h2" color="primary">
            ${walletBalance}
          </Typography>
        </Card>
        <Box display="flex" flexDirection="column" justifyContent="space-between" height="60%" width="100%">
          <Tabs value={tab} onChange={handleTabChange} sx={{ width: '100%' }} centered>
            <Tab label="Mint" />
            <Tab label="Transfer" />
            <Tab label="Faucet" />
            <Tab label="Send" />
          </Tabs>
          <TabPanel index={0} tab={tab} title="Mint">
            <form onSubmit={mint}>
              <Box
                sx={{
                  backgroundColor: (theme) => theme.palette.grey['200'],
                }}
                borderRadius={(theme) => `${theme.shape.borderRadius}px`}
                display="flex"
                justifyContent="center"
              >
                <SubmitButtonWithProgress label="Mint" running={minting} sx={{ m: 2 }} />
                {tokenId && (
                  <Card
                    sx={{
                      backgroundColor: (theme) => theme.palette.grey['100'],
                      m: 2,
                      ml: 0,
                      py: 0,
                      px: 1,
                      width: '100%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <Typography color="text.secondary">
                      Token ID:{' '}
                      <Typography component="span" color="text.primary" fontWeight="bold">
                        {tokenId}
                      </Typography>
                    </Typography>
                    <Button sx={{ p: 0, m: 0, minWidth: 0 }} onClick={copyTokenId}>
                      <Copy sx={{ color: 'primary.main' }} />
                    </Button>
                  </Card>
                )}
              </Box>
            </form>
          </TabPanel>
          <TabPanel index={1} tab={tab} title="Transfer token">
            <TransferForm
              tokenProxy={tokenProxy}
              user={user}
              formValues={transferFormValues}
              onChange={handleFormChange(setTransferFormValues)}
              onSuccess={() =>
                setSnackbarState({
                  open: true,
                  message: 'Token transferred successfully.',
                  severity: 'success',
                })
              }
              onFailure={(message?: string) =>
                setSnackbarState({
                  open: true,
                  message: message || 'Something went wrong. Please check the console.',
                  severity: 'error',
                })
              }
            />
          </TabPanel>
          <TabPanel index={2} tab={tab} title="Faucet">
            <form onSubmit={transferFromFaucet}>
              <Box
                sx={{
                  backgroundColor: (theme) => theme.palette.grey['200'],
                }}
                borderRadius={(theme) => `${theme.shape.borderRadius}px`}
                display="flex"
                justifyContent="center"
              >
                <SubmitButtonWithProgress label="Get $100" running={faucetRunning} sx={{ m: 2 }} />
              </Box>
            </form>
          </TabPanel>
          <TabPanel index={3} tab={tab} title="Send tokens">
            <SendCoinsForm
              coinContractProxy={coinProxy}
              user={user}
              values={sendCoinsFormValues}
              onChange={handleFormChange(setSendCoinsFormValues)}
              onSuccess={() => {
                setSnackbarState({ open: true, severity: 'success', message: 'Tokens sent successfully.' });
              }}
              onFailure={(message?: string) =>
                setSnackbarState({
                  open: true,
                  severity: 'error',
                  message: message || 'Something went wrong. Please check the console.',
                })
              }
            />
          </TabPanel>
        </Box>
      </Card>
      <CustomSnackbar {...snackbarState} onClose={onSnackbarClose} />
    </Container>
  );
};

export default Wallet;
