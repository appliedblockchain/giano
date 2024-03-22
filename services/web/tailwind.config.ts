import forms from '@tailwindcss/forms';
import typography from '@tailwindcss/typography';
import daisyui from 'daisyui';
import type { Config } from 'tailwindcss';

export default {
  content: ['./src/**/*.{html,js,ts,jsx,tsx}'],
  plugins: [typography, forms, daisyui],
  theme: {
    extend: {
      colors: {
        'primary-main': 'rgba(111, 89, 240, 1)',
        'primary-dark': '',
        'primary-light': '',
        'primary-main-gradient': '',
      },
    },
  },
  daisyui: {
    logs: false,
  },
} satisfies Config;
