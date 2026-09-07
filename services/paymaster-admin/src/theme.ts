import { createSystem, defaultConfig, defineConfig } from '@chakra-ui/react';

/**
 * The same brand tokens as the sample dApp — indigo primary, emerald accent, Inter — so the two
 * surfaces read as one product.
 *
 * The gradient page background is deliberately dropped. This is a dense operational console with
 * tables and numbers rather than a showcase, and a saturated backdrop behind a data table costs
 * legibility for nothing. `surface` and `canvas` give the panels a flat, quiet ground instead.
 */
const config = defineConfig({
  globalCss: {
    'html, body, #root': { minHeight: '100vh' },
    body: {
      background: 'canvas',
      color: 'fg',
      fontFamily: 'body',
    },
  },
  theme: {
    tokens: {
      fonts: {
        heading: { value: 'Inter, system-ui, -apple-system, sans-serif' },
        body: { value: 'Inter, system-ui, -apple-system, sans-serif' },
        mono: { value: 'ui-monospace, SFMono-Regular, Menlo, monospace' },
      },
      colors: {
        brand: {
          50: { value: '#eef2ff' },
          100: { value: '#e0e7ff' },
          200: { value: '#c7d2fe' },
          300: { value: '#a5b4fc' },
          400: { value: '#818cf8' },
          500: { value: '#6366f1' },
          600: { value: '#4338ca' },
          700: { value: '#3730a3' },
          800: { value: '#312e81' },
          900: { value: '#1e1b4b' },
          950: { value: '#130f38' },
        },
        accent: {
          50: { value: '#ecfdf5' },
          100: { value: '#d1fae5' },
          500: { value: '#10b981' },
          600: { value: '#059669' },
          700: { value: '#047857' },
        },
      },
    },
    semanticTokens: {
      colors: {
        canvas: { value: { base: '{colors.gray.50}', _dark: '{colors.gray.950}' } },
        surface: { value: { base: 'white', _dark: '{colors.gray.900}' } },
        brand: {
          solid: { value: '{colors.brand.600}' },
          contrast: { value: 'white' },
          fg: { value: '{colors.brand.700}' },
          muted: { value: '{colors.brand.100}' },
          subtle: { value: '{colors.brand.50}' },
          emphasized: { value: '{colors.brand.700}' },
          focusRing: { value: '{colors.brand.600}' },
        },
        accent: {
          solid: { value: '{colors.accent.600}' },
          contrast: { value: 'white' },
          fg: { value: '{colors.accent.700}' },
          muted: { value: '{colors.accent.100}' },
          subtle: { value: '{colors.accent.50}' },
          emphasized: { value: '{colors.accent.700}' },
          focusRing: { value: '{colors.accent.600}' },
        },
      },
    },
  },
});

export const system = createSystem(defaultConfig, config);
