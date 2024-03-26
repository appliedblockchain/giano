import React, { useState } from 'react';
import { Box, Button, Card, CircularProgress, Container, Select, Tab, Tabs, Typography } from '@mui/material';

const Mint: React.FC = () => {
  const [tab, setTab] = useState(0);
  const [minting, setMinting] = useState(false);

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
      setTimeout(() => setMinting(false), 2000);
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
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <Box display="flex" justifyContent="space-between" width="100%">
          <img alt="Giano logo" src="/logo_horizontal.svg" />
          <Select />
        </Box>
        <Card sx={{ backgroundColor: 'grey.100', width: '100%', textAlign: 'center', p: '16 40 16 40' }}>
          <Typography color="primary">Available</Typography>
          <Typography variant="h2" color="primary">
            $21.67
          </Typography>
        </Card>
        <Box display="flex" flexDirection="column" justifyContent="space-between" height="50%" width="100%">
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
                    '&.Mui-disabled': { backgroundColor: (theme) => theme.palette.primary.dark },
                    m: 2,
                    width: '100%',
                  }}
                >
                  {minting ? <CircularProgress size="18px" sx={{ margin: '5px', color: 'white' }} /> : 'Mint'}
                </Button>
              </Box>
            </Box>
          </TabPanel>
        </Box>
      </Card>
    </Container>
  );
};

export default Mint;
