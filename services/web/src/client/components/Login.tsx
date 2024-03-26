import React from 'react';
import { Box, Button, Card, Container, Divider, TextField, Typography } from '@mui/material';

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
          padding: '30px',
          gap: '30px',
        }}
      >
        <img alt="Giano logo" src="/logo.svg" />
        <form>
          <Button variant="contained">Login</Button>
        </form>
        <Divider flexItem>
          <Typography>or</Typography>
        </Divider>
        <form style={{ display: 'flex', flexDirection: 'column', textAlign: 'center', width: '100%', gap: 'inherit' }}>
          <Typography variant="h4">Create account</Typography>
          <TextField label="Passkey" />
          <Button variant="contained" disabled>
            Create account
          </Button>
        </form>
      </Card>
    </Container>
  );
};

export default Login;
