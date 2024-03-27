import React, { useState } from 'react';
import { Box, Button, Card, CircularProgress, Container, FormControl, MenuItem, Select, Tab, Tabs, TextField, Typography } from '@mui/material';
import { Copy } from '../icons';

const Wallet: React.FC = () => {
  const [tab, setTab] = useState(1);
  const [minting, setMinting] = useState(false);
  const [transferring, setTransferring] = useState(false);
  const [tokenId, setTokenId] = useState('');

  const handleTabChange = (_event: React.SyntheticEvent, newTab: number) => {
    setTab(newTab);
  };

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

  const mint = (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (!minting) {
      setMinting(true);
      setTimeout(() => {
        setMinting(false);
        setTokenId(tokenId ? (parseInt(tokenId) + 1).toString() : '1');
        setOpenSnackbar(true);
      }, 2000);
    }
  };

  const transfer = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const { currentTarget: form } = e;
    const { recipient, tokenId } = Object.fromEntries(new FormData(form));
    console.log({ recipient, tokenId });
  };

  const send = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const { currentTarget: form } = e;
    const { recipient, amount } = Object.fromEntries(new FormData(form));
    console.log({ recipient, amount });
  };

  const copyTokenId = async () => {
    await window.navigator.clipboard.writeText(tokenId);
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
              <MenuItem value="1">0x12312321312</MenuItem>
            </Select>
          </FormControl>
        </Box>
        <Card sx={{ backgroundColor: 'grey.100', width: '100%', textAlign: 'center', p: '16 40 16 40' }}>
          <Typography color="primary">Available</Typography>
          <Typography variant="h2" color="primary">
            $21.67
          </Typography>
        </Card>
        <Box display="flex" flexDirection="column" justifyContent="space-between" height="60%" width="100%">
          <Tabs value={tab} onChange={handleTabChange} sx={{ width: '100%' }} centered>
            <Tab label="Mint" />
            <Tab label="Transfer" />
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
                      <Typography display="inline" color="text.primary" fontWeight="bold">
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
              <form style={{ display: 'flex', flexDirection: 'column', gap: 20 }} onSubmit={transfer}>
                <TextField name="recipient" label="Recipient address" variant="standard" required />
                <TextField name="tokenId" label="Token ID" type="number" required />
                <Button type="submit" disabled={transferring} variant="contained">
                  {transferring ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Transfer token'}
                </Button>
              </form>
            </Box>
          </TabPanel>
          <TabPanel index={2} tab={tab}>
            <Box display="flex" flexDirection="column" justifyContent="space-between" height="100%">
              <Typography variant="h4" color="primary" align="center">
                Send tokens
              </Typography>
              <form style={{ display: 'flex', flexDirection: 'column', gap: 20 }} onSubmit={send} onInvalid={(e) => e.preventDefault()}>
                <TextField name="recipient" label="Recipient address" variant="standard" required />
                <TextField name="amount" label="Amount" type="number" required />
                <Button type="submit" disabled={transferring} variant="contained">
                  {transferring ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Send'}
                </Button>
              </form>
            </Box>
          </TabPanel>
        </Box>
      </Card>
    </Container>
  );
};

export default Wallet;
