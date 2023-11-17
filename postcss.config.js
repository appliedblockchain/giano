import autoprefixer from 'autoprefixer';
import postcssImport from 'postcss-import';
import tailwindcssNesting from 'tailwindcss/nesting/index.js';
import tailwindcss from 'tailwindcss';

export default {
  plugins: [autoprefixer, postcssImport, tailwindcssNesting, tailwindcss],
};
