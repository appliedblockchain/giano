import forms from '@tailwindcss/forms';
import typography from '@tailwindcss/typography';
import daisyui from 'daisyui';
import type { Config } from 'tailwindcss';

export default {
  content: ['./src/**/*.{html,js,ts,jsx,tsx}'],
  plugins: [typography, forms, daisyui],
  daisyui: {
    logs: false,
    themes: ['lofi'],
  },
} satisfies Config;
