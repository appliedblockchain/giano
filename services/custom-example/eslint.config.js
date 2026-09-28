// Lint guards for the reference dApp (design.md D2, D10).
//
// Two rules are load-bearing and the rest is hygiene:
//   * the demo may import Giano ONLY through the published connector entry point — anything else
//     validates a path no client can reproduce (R2);
//   * the demo writes no CSS — no stylesheets, no `css` prop, no `style` attribute; Chakra
//     components and theme tokens are the whole vocabulary (R4). The one stylesheet allowed is
//     RainbowKit's own, because it is the library's, not ours.
import js from '@eslint/js';
import react from 'eslint-plugin-react';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'node_modules/', 'scripts/', 'public/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    plugins: { react },
    languageOptions: { globals: { ...globals.browser }, parserOptions: { ecmaFeatures: { jsx: true } } },
    settings: { react: { version: 'detect' } },
    rules: {
      ...react.configs.flat.recommended.rules,
      ...react.configs.flat['jsx-runtime'].rules,
      'react/prop-types': 'off',
      '@typescript-eslint/consistent-type-definitions': ['error', 'type'],
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],

      // R2 — published surface only.
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@appliedblockchain/*', '!@appliedblockchain/giano-connector'],
              message: 'The demo may only import @appliedblockchain/giano-connector — the same artifact a client installs (R2).',
            },
            {
              group: ['@appliedblockchain/giano-connector/*'],
              message: 'Only the default entry point of the connector is public (R2).',
            },
            {
              group: ['../../*', '**/packages/*', '**/services/*'],
              message: 'A relative import that leaves services/custom-example/src reaches into workspace internals (R2).',
            },
            {
              group: ['*.css', '!@rainbow-me/rainbowkit/styles.css'],
              message: 'No stylesheets: Chakra components and theme tokens only (R4). RainbowKit ships its own stylesheet, which is allowed.',
            },
          ],
        },
      ],

      // R4 — no custom CSS on elements or components.
      'react/forbid-dom-props': ['error', { forbid: [{ propName: 'style', message: 'No inline style: use Chakra style props (R4).' }] }],
      'react/forbid-component-props': [
        'error',
        {
          forbid: [
            { propName: 'style', message: 'No inline style: use Chakra style props (R4).' },
            { propName: 'css', message: 'No css prop: use Chakra style props and theme tokens (R4).' },
          ],
        },
      ],
    },
  },
  {
    // One level deeper: `../../theme` from src/components/ui is still inside src.
    files: ['src/components/ui/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            { group: ['@appliedblockchain/*', '!@appliedblockchain/giano-connector'], message: 'The demo may only import @appliedblockchain/giano-connector (R2).' },
            { group: ['../../../*', '**/packages/*', '**/services/*'], message: 'A relative import that leaves services/custom-example/src reaches into workspace internals (R2).' },
            { group: ['*.css', '!@rainbow-me/rainbowkit/styles.css'], message: 'No stylesheets (R4).' },
          ],
        },
      ],
    },
  },
);
