/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_WALLET_VERSION?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
