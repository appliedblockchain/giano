import React, { useCallback, useEffect, useMemo, useState } from 'react';
import type { Account, GenericERC721 } from '@giano/contracts/typechain-types';
import { Account__factory, GenericERC20__factory, GenericERC721__factory } from '@giano/contracts/typechain-types';
import { Logout } from '@mui/icons-material';
import { Box, Button, Card, CircularProgress, Container, FormControl, MenuItem, Select, Tab, Tabs, TextField, Typography } from '@mui/material';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import type { Addressable } from 'ethers';
import { ethers } from 'ethers';
import { getCredential } from 'services/web/src/client/common/credentials';
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
  accountContract?: Account;
  tokenContract: GenericERC721;
  user?: User;
  formValues: TransferFormValues;
  onSuccess: () => void;
  onFailure: () => void;
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

const TransferForm = ({ user, accountContract, onSuccess, onFailure, tokenContract, formValues, onChange }: TransferFormProps) => {
  const [transferring, setTransferring] = useState(false);
  const transfer = async (e) => {
    e.preventDefault();
    setTransferring(true);
    try {
      if (accountContract && user) {
        console.log(accountContract.target);
        const { recipient, tokenId } = formValues;
        const signature = await signAndEncodeChallenge(user, accountContract);
        const tx = await accountContract.transferToken(tokenContract.target, recipient, tokenId, signature);
        await tx.wait();
        onSuccess();
      }
    } catch (e) {
      console.error(e);
      onFailure();
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
      <Button type="submit" disabled={transferring} variant="contained">
        {transferring ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Transfer token'}
      </Button>
    </form>
  );
};

type SendCoinsFormValues = {
  recipient: string;
  amount: string;
};

type SendCoinsFormProps = {
  accountContract?: Account;
  user?: User;
  coinContractAddress: string | Addressable;
  values: SendCoinsFormValues;
  onSuccess: () => void;
  onFailure: () => void;
  onChange: (e: React.SyntheticEvent) => void;
};

const SendCoinsForm: React.FC<SendCoinsFormProps> = ({ accountContract, user, onSuccess, onFailure, coinContractAddress, values, onChange }) => {
  const [sending, setSending] = useState(false);

  const send = async (e: React.FormEvent<HTMLFormElement>) => {
    try {
      if (accountContract && user) {
        e.preventDefault();
        setSending(true);
        const signature = await signAndEncodeChallenge(user, accountContract);
        const tx = await accountContract.transferERC20(coinContractAddress, values.recipient, ethers.parseEther(values.amount), signature);
        await tx.wait();
        onSuccess();
      }
    } catch (e) {
      console.error(e);
      onFailure();
    } finally {
      setSending(false);
    }
  };

  return (
    <form style={{ display: 'flex', flexDirection: 'column', gap: 20 }} onSubmit={send}>
      <TextField value={values.recipient} onChange={onChange} name="recipient" label="Recipient address" variant="standard" required disabled={sending} />
      <TextField value={values.amount} onChange={onChange} name="amount" label="Amount" type="number" required disabled={sending} />
      <Button type="submit" variant="contained" disabled={sending}>
        {sending ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Send'}
      </Button>
    </form>
  );
};

async function signAndEncodeChallenge(user: User, accountContract: Account) {
  const challengeHex = await accountContract.getChallenge();
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
  const accountContract = useMemo(() => (user ? Account__factory.connect(user.account, signer) : undefined), [user?.account, signer]);
  const tokenContract = useMemo(() => GenericERC721__factory.connect('0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', signer), [signer]);
  const coinContract = useMemo(() => GenericERC20__factory.connect('0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0', signer), [signer]);

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
    console.log('mounting wallet');
    const cleanup = () => console.log('unmounting wallet');
    const user = getSessionUser();
    if (!user) {
      window.location.replace('/');
      return cleanup;
    }
    setUser(user);
    return cleanup;
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

  const transferFromFaucet = async () => {
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
            <Select labelId="account-select-label" value="1">
              <MenuItem value="1">{user?.account}</MenuItem>
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
            <Box
              sx={{
                backgroundColor: (theme) => theme.palette.grey['200'],
              }}
              borderRadius={(theme) => `${theme.shape.borderRadius}px`}
              display="flex"
              justifyContent="center"
            >
              <Button
                disabled={minting}
                onClick={mint}
                variant="contained"
                sx={{
                  '&.Mui-disabled': { backgroundColor: 'primary.dark' },
                  m: 2,
                  width: '100%',
                }}
              >
                {minting ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Mint'}
              </Button>
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
          </TabPanel>
          <TabPanel index={1} tab={tab} title="Transfer token">
            <TransferForm
              accountContract={accountContract}
              tokenContract={tokenContract}
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
              onFailure={() =>
                setSnackbarState({
                  open: true,
                  message: 'Something went wrong. Please check the console.',
                  severity: 'error',
                })
              }
            />
          </TabPanel>
          <TabPanel index={2} tab={tab} title="Faucet">
            <Box
              sx={{
                backgroundColor: (theme) => theme.palette.grey['200'],
              }}
              borderRadius={(theme) => `${theme.shape.borderRadius}px`}
              display="flex"
              justifyContent="center"
            >
              <Button
                disabled={faucetRunning}
                onClick={transferFromFaucet}
                variant="contained"
                sx={{
                  '&.Mui-disabled': { backgroundColor: 'primary.dark' },
                  m: 2,
                  width: '100%',
                }}
              >
                {faucetRunning ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Get $100'}
              </Button>
            </Box>
          </TabPanel>
          <TabPanel index={3} tab={tab} title="Send tokens">
            <SendCoinsForm
              accountContract={accountContract}
              coinContractAddress={coinContract.target}
              user={user}
              values={sendCoinsFormValues}
              onChange={handleFormChange(setSendCoinsFormValues)}
              onSuccess={() => {
                setSnackbarState({ open: true, severity: 'success', message: 'Tokens sent successfully.' });
              }}
              onFailure={() =>
                setSnackbarState({
                  open: true,
                  severity: 'error',
                  message: 'Something went wrong. Please check the console.',
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
