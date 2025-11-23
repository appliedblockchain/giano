import CssBaseline from '@mui/material/CssBaseline';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { AppProps } from 'next/app';
import { WagmiProvider } from 'wagmi';
// import { RainbowKitProvider } from '@rainbow-me/rainbowkit';
import { config } from '../wagmi';
import '../styles/globals.css';
import '@rainbow-me/rainbowkit/styles.css';

const client = new QueryClient();

// Create a Material UI theme with high contrast and gradient background
const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#4338ca', // Darker indigo for higher contrast
      light: '#6366f1',
      dark: '#3730a3',
      contrastText: '#ffffff',
    },
    secondary: {
      main: '#059669', // Darker emerald for higher contrast
      light: '#10b981',
      dark: '#047857',
      contrastText: '#ffffff',
    },
    success: {
      main: '#059669', // Darker emerald
      light: '#10b981',
      dark: '#047857',
      contrastText: '#ffffff',
    },
    error: {
      main: '#dc2626', // Darker red for higher contrast
      light: '#ef4444',
      dark: '#b91c1c',
      contrastText: '#ffffff',
    },
    warning: {
      main: '#d97706', // Darker amber for higher contrast
      light: '#f59e0b',
      dark: '#b45309',
      contrastText: '#ffffff',
    },
    info: {
      main: '#2563eb', // Darker blue for higher contrast
      light: '#3b82f6',
      dark: '#1d4ed8',
      contrastText: '#ffffff',
    },
    background: {
      default: '#ffffff', // Pure white background
      paper: '#ffffff',
    },
    text: {
      primary: '#0f172a', // Very dark text for maximum contrast
      secondary: '#334155', // Darker secondary text
    },
    divider: '#e2e8f0', // Darker divider for better visibility
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontWeight: 700,
      fontSize: '2.5rem',
      color: '#0f172a',
    },
    h2: {
      fontWeight: 600,
      fontSize: '2rem',
      color: '#0f172a',
    },
    h3: {
      fontWeight: 600,
      fontSize: '1.75rem',
      color: '#0f172a',
    },
    h4: {
      fontWeight: 600,
      fontSize: '1.5rem',
      color: '#0f172a',
    },
    h5: {
      fontWeight: 600,
      fontSize: '1.25rem',
      color: '#0f172a',
    },
    h6: {
      fontWeight: 600,
      fontSize: '1.125rem',
      color: '#0f172a',
    },
    button: {
      fontWeight: 600,
      textTransform: 'none',
    },
    body1: {
      color: '#0f172a',
    },
    body2: {
      color: '#334155',
    },
  },
  shape: {
    borderRadius: 12,
  },
  components: {
    MuiCssBaseline: {
      styleOverrides: {
        body: {
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          backgroundAttachment: 'fixed',
          minHeight: '100vh',
          margin: 0,
          padding: 0,
        },
        '#__next': {
          minHeight: '100vh',
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          backgroundAttachment: 'fixed',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: '10px 20px',
          fontWeight: 600,
          fontSize: '0.875rem',
        },
        contained: {
          boxShadow: '0 2px 4px 0 rgba(0, 0, 0, 0.2), 0 1px 2px 0 rgba(0, 0, 0, 0.1)',
          '&:hover': {
            boxShadow: '0 4px 8px -1px rgba(0, 0, 0, 0.2), 0 2px 4px -1px rgba(0, 0, 0, 0.1)',
          },
        },
        outlined: {
          borderWidth: '2px',
          '&:hover': {
            borderWidth: '2px',
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          borderRadius: 12,
          border: '1px solid rgba(255, 255, 255, 0.2)',
          backgroundColor: 'rgba(255, 255, 255, 0.95)',
          backdropFilter: 'blur(10px)',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
          border: '1px solid rgba(255, 255, 255, 0.2)',
          backgroundColor: 'rgba(255, 255, 255, 0.95)',
          backdropFilter: 'blur(10px)',
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          border: '1px solid',
          backdropFilter: 'blur(10px)',
          '&.MuiAlert-standardSuccess': {
            borderColor: '#059669',
            backgroundColor: 'rgba(240, 253, 244, 0.95)',
          },
          '&.MuiAlert-standardError': {
            borderColor: '#dc2626',
            backgroundColor: 'rgba(254, 242, 242, 0.95)',
          },
          '&.MuiAlert-standardWarning': {
            borderColor: '#d97706',
            backgroundColor: 'rgba(255, 251, 235, 0.95)',
          },
          '&.MuiAlert-standardInfo': {
            borderColor: '#2563eb',
            backgroundColor: 'rgba(239, 246, 255, 0.95)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 6,
          fontWeight: 600,
          backdropFilter: 'blur(10px)',
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            backgroundColor: 'rgba(255, 255, 255, 0.9)',
            backdropFilter: 'blur(10px)',
            '& fieldset': {
              borderColor: '#cbd5e1',
              borderWidth: '2px',
            },
            '&:hover fieldset': {
              borderColor: '#94a3b8',
            },
            '&.Mui-focused fieldset': {
              borderColor: '#4338ca',
              borderWidth: '2px',
            },
          },
        },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: {
          color: '#334155',
          '&.Mui-focused': {
            color: '#4338ca',
          },
        },
      },
    },
    MuiTypography: {
      styleOverrides: {
        root: {
          '&.MuiTypography-colorTextSecondary': {
            color: '#334155',
          },
        },
      },
    },
    MuiDivider: {
      styleOverrides: {
        root: {
          borderColor: 'rgba(226, 232, 240, 0.5)',
        },
      },
    },
    MuiContainer: {
      styleOverrides: {
        root: {
          paddingTop: '2rem',
          paddingBottom: '2rem',
        },
      },
    },
  },
});

function MyApp({ Component, pageProps }: AppProps) {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <WagmiProvider config={config}>
        <QueryClientProvider client={client}>
          {/* <RainbowKitProvider> */}
          <Component {...pageProps} />
          {/* </RainbowKitProvider> */}
        </QueryClientProvider>
      </WagmiProvider>
    </ThemeProvider>
  );
}

export default MyApp;
