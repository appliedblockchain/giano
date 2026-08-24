import { Box, Heading, Text } from '@chakra-ui/react';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { Provider, Toaster } from './components/ui';
import { loadAdminConfig } from './config';

/**
 * Configuration is loaded before the first render, and a failure to load it renders an
 * explanation rather than an empty page: an admin console that cannot tell you which chain it is
 * pointed at should not render controls that write to one.
 */
const root = createRoot(document.getElementById('root')!);

loadAdminConfig()
  .then(() => {
    root.render(
      <StrictMode>
        <Provider>
          <App />
          <Toaster />
        </Provider>
      </StrictMode>,
    );
  })
  .catch((error: Error) => {
    root.render(
      <Provider>
        <Box p="8">
          <Heading size="md" mb="2">
            Paymaster admin is misconfigured
          </Heading>
          <Text color="fg.muted">{error.message}</Text>
          <Text color="fg.muted" mt="2" fontSize="sm">
            /config.json must set at least <code>chainId</code> and <code>rpcUrl</code>.
          </Text>
        </Box>
      </Provider>,
    );
  });
