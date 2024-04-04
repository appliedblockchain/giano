import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Account__factory, ERC20__factory, GenericERC20__factory, GenericERC721__factory } from '@giano/contracts/typechain-types';
import { Logout } from '@mui/icons-material';
import { Box, Button, Card, CircularProgress, Container, FormControl, MenuItem, Select, Tab, Tabs, TextField, Typography } from '@mui/material';
import { ECDSASigValue } from '@peculiar/asn1-ecc';
import { AsnParser } from '@peculiar/asn1-schema';
import { ContractEventPayload, ethers, ProviderEvent } from 'ethers';
import { getCredential } from 'services/web/src/client/common/credentials';
import { hexToUint8Array, uint8ArrayToUint256 } from 'services/web/src/client/common/uint';
import type { User } from 'services/web/src/client/common/user';
import { getSessionUser } from 'services/web/src/client/common/user';
import type { CustomSnackbarProps } from 'services/web/src/client/components/CustomSnackbar';
import CustomSnackbar from 'services/web/src/client/components/CustomSnackbar';
import { Copy } from '../icons';

type TransferFormProps = {
  recipient: string;
  tokenId: string;
};

const faucetDropAmount = ethers.parseEther('100');

function TransferForm(props: { onSubmit: (f: TransferFormProps) => Promise<void> }) {
  const [transferForm, setTransferForm] = useState<TransferFormProps>({ recipient: '', tokenId: '' });
  const [transferring, setTransferring] = useState(false);
  const handleChange = (event) => {
    const { name, value } = event.target;
    setTransferForm((prev) => ({
      ...prev,
      [name]: value,
    }));
  };
  return (
    <form
      style={{ display: 'flex', flexDirection: 'column', gap: 20 }}
      onSubmit={async (e) => {
        e.preventDefault();
        setTransferring(true);
        try {
          await props.onSubmit(transferForm);
        } finally {
          setTransferring(false);
        }
      }}
    >
      <TextField name="recipient" value={transferForm.recipient} onChange={handleChange} label="Recipient address" variant="standard" required />
      <TextField name="tokenId" value={transferForm.tokenId} label="Token ID" type="number" onChange={handleChange} required />
      <Button type="submit" disabled={transferring} variant="contained">
        {transferring ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Transfer token'}
      </Button>
    </form>
  );
}

const Wallet: React.FC = () => {
  const [tab, setTab] = useState(0);
  const [minting, setMinting] = useState(false);
  const [tokenId, setTokenId] = useState('');
  const [user, setUser] = useState<User | null>(null);
  const [snackbarState, setSnackbarState] = useState<CustomSnackbarProps | null>(null);
  const [walletBalance, setWalletBalance] = useState<string | null>(null);
  const [faucetRunning, setFaucetRunning] = useState(false);

  const provider = useMemo(() => new ethers.WebSocketProvider('ws://localhost:8545'), []);
  const signer = useMemo(() => new ethers.Wallet('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80', provider), [provider]);
  const tokenContract = useMemo(() => GenericERC721__factory.connect('0xe7f1725e7734ce288f8367e1bb143e90bb3f0512', signer), [signer]);
  const coinContract = useMemo(() => GenericERC20__factory.connect('0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0', signer), [signer]);

  useEffect(() => {
    // Typechain-generated event listener is not working
    const ethersContract = new ethers.Contract(coinContract.target, coinContract.interface, provider);
    if (walletBalance === null && user) {
      void coinContract.balanceOf(user.account).then((b) => setWalletBalance(ethers.formatEther(b)));
    }
    const listener = async (from, to) => {
      if (user && [from, to].map((a) => a.toLowerCase()).includes(user.account.toLowerCase())) {
        const balance = await coinContract.balanceOf(user.account);
        setWalletBalance(ethers.formatEther(balance));
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

  type TabPanelProps = {
    children?: React.ReactNode;
    index: number;
    tab: number;
    [other: string]: any;
  };

  const TabPanel: React.FC<TabPanelProps> = ({ children, tab, index, ...other }: TabPanelProps) => {
    return (
      <div role="tabpanel" style={{ width: '100%', height: '100%' }} hidden={tab !== index} id={`tab-${index}`} {...other}>
        {tab === index && children}
      </div>
    );
  };

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

  const transfer = async (form: TransferFormProps) => {
    if (!user) {
      throw new Error('Not logged in');
    }
    try {
      const { recipient, tokenId } = form;
      const accountContract = Account__factory.connect(user.account, signer);
      const { x, y } = await accountContract.publicKey();
      const challengeHex = await accountContract.getChallenge();
      const challenge = hexToUint8Array(challengeHex);

      const credential = await getCredential(user.rawId, challenge);

      const parsedSignature = AsnParser.parse(credential.response.signature, ECDSASigValue);

      const clientDataJson = new TextDecoder().decode(credential.response.clientDataJSON);
      const responseTypeLocation = clientDataJson.indexOf('"type":');
      const challengeLocation = clientDataJson.indexOf('"challenge":');
      const signature = ethers.AbiCoder.defaultAbiCoder().encode(
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
      const tx = await accountContract.transferToken(tokenContract.target, recipient, tokenId, signature);
      await tx.wait();
      setSnackbarState({ severity: 'success', message: 'Token transferred successfully.', open: true });
    } catch (e) {
      console.error(e);
      setSnackbarState({ severity: 'error', message: 'Something went wrong. Please check the console.', open: true });
    }
  };

  const send = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const { currentTarget: form } = e;
    const { recipient, amount } = Object.fromEntries(new FormData(form));
    setSnackbarState({ severity: 'success', message: 'Amount sent successfully.', open: true });
    console.log({ recipient, amount });
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
    setUser(null);
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
          <TabPanel index={0} tab={tab}>
            <Box display="flex" flexDirection="column" justifyContent="space-around" height="100%">
              <Typography variant="h4" color="primary" align="center">
                Mint
              </Typography>
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
            </Box>
          </TabPanel>
          <TabPanel index={1} tab={tab}>
            <Box display="flex" flexDirection="column" justifyContent="space-between" height="100%">
              <Typography variant="h4" color="primary" align="center">
                Transfer token
              </Typography>
              <TransferForm onSubmit={transfer} />
            </Box>
          </TabPanel>
          <TabPanel index={2} tab={tab}>
            <Box display="flex" flexDirection="column" justifyContent="space-between" height="100%">
              <Typography variant="h4" color="primary" align="center">
                Faucet
              </Typography>
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
            </Box>
          </TabPanel>
          <TabPanel index={3} tab={tab}>
            <Box display="flex" flexDirection="column" justifyContent="space-between" height="100%">
              <Typography variant="h4" color="primary" align="center">
                Send tokens
              </Typography>
              <form style={{ display: 'flex', flexDirection: 'column', gap: 20 }} onSubmit={send} onInvalid={(e) => e.preventDefault()}>
                <TextField name="recipient" label="Recipient address" variant="standard" required />
                <TextField name="amount" label="Amount" type="number" required />
                <Button type="submit" disabled variant="contained">
                  Send
                </Button>
              </form>
            </Box>
          </TabPanel>
        </Box>
      </Card>
      <CustomSnackbar {...snackbarState} onClose={onSnackbarClose} />
    </Container>
  );
};

export default Wallet;
