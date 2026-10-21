---
'@appliedblockchain/giano-paymaster-sdk': patch
---

Built with tsdown instead of tsup, with declarations generated from source by oxc
(`isolatedDeclarations`) rather than by the TypeScript compiler. Same entry points, file names,
exports and types: the declarations are identical as a consumer sees them (every export, member by
member) and compile with TypeScript 5.0.4 through 7.0. The CLI's output is unchanged. The library
bundle no longer shares a chunk with the CLI, so `dist/index.mjs` is self-contained.
