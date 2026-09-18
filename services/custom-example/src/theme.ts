import { createSystem, defaultConfig, defineConfig } from '@chakra-ui/react';

/**
 * The ONLY place brand appears (design.md D10). Every component says `colorPalette="brand"` (or
 * `accent`) and nothing else about colour; swap the values below for the Applied Edge Design System
 * export (tasks 1.3/1.4) and nothing else changes.
 *
 * PLACEHOLDER VALUES: the indigo/emerald pair carried over from the previous demo, kept under the final
 * token names until the Applied Blockchain tokens arrive. No globalCss, no custom CSS anywhere (R4).
 */
const config = defineConfig({
  theme: {
    tokens: {
      fonts: {
        heading: { value: 'system-ui, -apple-system, "Segoe UI", sans-serif' },
        body: { value: 'system-ui, -apple-system, "Segoe UI", sans-serif' },
        mono: { value: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace' },
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
          200: { value: '#a7f3d0' },
          300: { value: '#6ee7b7' },
          400: { value: '#34d399' },
          500: { value: '#10b981' },
          600: { value: '#059669' },
          700: { value: '#047857' },
          800: { value: '#065f46' },
          900: { value: '#064e3b' },
          950: { value: '#022c22' },
        },
      },
    },
    semanticTokens: {
      colors: {
        brand: {
          solid: { value: { _light: '{colors.brand.600}', _dark: '{colors.brand.400}' } },
          contrast: { value: { _light: 'white', _dark: '{colors.brand.950}' } },
          fg: { value: { _light: '{colors.brand.700}', _dark: '{colors.brand.300}' } },
          muted: { value: { _light: '{colors.brand.100}', _dark: '{colors.brand.900}' } },
          subtle: { value: { _light: '{colors.brand.50}', _dark: '{colors.brand.950}' } },
          emphasized: { value: { _light: '{colors.brand.700}', _dark: '{colors.brand.300}' } },
          focusRing: { value: { _light: '{colors.brand.600}', _dark: '{colors.brand.400}' } },
        },
        accent: {
          solid: { value: { _light: '{colors.accent.600}', _dark: '{colors.accent.400}' } },
          contrast: { value: { _light: 'white', _dark: '{colors.accent.950}' } },
          fg: { value: { _light: '{colors.accent.700}', _dark: '{colors.accent.300}' } },
          muted: { value: { _light: '{colors.accent.100}', _dark: '{colors.accent.900}' } },
          subtle: { value: { _light: '{colors.accent.50}', _dark: '{colors.accent.950}' } },
          emphasized: { value: { _light: '{colors.accent.700}', _dark: '{colors.accent.300}' } },
          focusRing: { value: { _light: '{colors.accent.600}', _dark: '{colors.accent.400}' } },
        },
      },
    },
  },
});

export const system = createSystem(defaultConfig, config);
