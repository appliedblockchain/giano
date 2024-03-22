import React from 'react';
import { Box, Button, Card, Container, Input, Typography } from '@mui/material';

const Login: React.FC = () => {
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
        }}
      >
        <img alt="Giano logo" src="/logo.svg" />
        <Box>
          <Button variant="contained">Login</Button>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <hr style={{ width: '128px', borderColor: 'rgba(0, 10, 30, 0.12)' }} />
          <p>or</p>
          <hr style={{ width: '128px', borderColor: 'rgba(0, 10, 30, 0.12)' }} />
        </Box>
        <Typography variant="h4">Create account</Typography>
        <form>
          <Input placeholder="Passkey name"></Input>
        </form>
      </Card>
    </Container>
  );
};

export default Login;
