import { createTheme } from '@mui/material';

export default createTheme({
  components: {
    MuiButton: {
      defaultProps: {
        disableElevation: true,
      },
      styleOverrides: {
        contained: {
          fontWeight: '900',
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: '12px',
        },
      },
    },
  },
  palette: {
    text: {
      primary: 'rgba(45, 44, 52, 1)',
      secondary: 'rgba(125, 129, 143, 1)',
      disabled: 'rgba(195, 197, 209, 1)',
    },
    background: {
      default: 'rgba(12, 23, 49, 1)',
    },
    primary: {
      light: 'rgba(180, 155, 255, 1)',
      main: 'rgba(111, 89, 240, 1)',
      dark: 'rgba(71, 57, 154, 1)',
    },
    grey: {
      '100': 'rgba(247, 248, 253, 1)',
      '200': 'rgba(236, 239, 250, 1)',
      '300': 'rgba(219, 221, 239, 1)',
      '400': 'rgba(196, 196, 215, 1)',
      '500': 'rgba(169, 171, 190, 1)',
      '600': 'rgba(128, 130, 149, 1)',
      '700': 'rgba(107, 107, 124, 1)',
      '800': 'rgba(74, 74, 86, 1)',
      '900': 'rgba(52, 52, 60, 1)',
    },
    error: {
      light: 'rgba(254, 214, 221, 1)',
      main: 'rgba(202, 43, 72, 1)',
      dark: 'rgba(102, 14, 30, 1)',
    },
  },
  typography: {
    h1: {
      fontWeight: 900,
      fontSize: 56,
      lineHeight: '70px',
    },
    h2: {
      fontWeight: 900,
      fontSize: 40,
      lineHeight: '50px',
    },
    h3: {
      fontWeight: 700,
      fontSize: 32,
      lineHeight: '40px',
    },
    h4: {
      fontWeight: 700,
      fontSize: 24,
      lineHeight: '30px',
    },
    h5: {
      fontWeight: 400,
      fontSize: 20,
      lineHeight: '30px',
    },
    h6: {
      fontWeight: 700,
      fontSize: 20,
      lineHeight: '24px',
    },
    fontSize: 16,
    fontFamily: ['"Source Sans 3"', 'sans-serif'].join(','),
  },
});
