// node --test scripts/migrate-chains-document.test.mjs
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { migrate } from './migrate-chains-document.mjs';

const flat = {
  chainId: 84532,
  name: 'Base Sepolia',
  rpcUrl: 'https://base.example/KEY',
  bundlerUrl: 'http://bundler-base-sepolia.giano-dev.local:4337',
  entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
  factory: '0x26dCd29390eba3B22BcCbd2143989E5994Ac7050',
  sponsorshipPaymaster: '0xf98b56de62ce88cEb70A9155582248cDBf2D0718',
  policy: { allowedPaymasters: ['0xf98b56de62ce88cEb70A9155582248cDBf2D0718'] },
  walletRpcUrl: 'https://sepolia.base.org',
  refreshSeconds: 15,
};

describe('migrate-chains-document', () => {
  it('sorts every field into the shared top level or its service section', () => {
    const { document, notes } = migrate([flat]);
    assert.deepEqual(document, [
      {
        chainId: 84532,
        name: 'Base Sepolia',
        rpcUrl: 'https://base.example/KEY',
        entryPoint: '0x0000000071727De22E5E9d8BAf0edAc6f37da032',
        sponsorshipPaymaster: '0xf98b56de62ce88cEb70A9155582248cDBf2D0718',
        walletApi: { factory: '0x26dCd29390eba3B22BcCbd2143989E5994Ac7050', policy: flat.policy },
        paymasterAdmin: { walletRpcUrl: 'https://sepolia.base.org', refreshSeconds: 15 },
      },
    ]);
    assert.match(notes[0], /chain 84532.*dropped bundlerUrl "http:\/\/bundler-base-sepolia/);
  });

  it('leaves out sections an entry has nothing for', () => {
    assert.deepEqual(migrate([{ chainId: 1, name: 'A', rpcUrl: 'http://a' }]).document, [{ chainId: 1, name: 'A', rpcUrl: 'http://a' }]);
  });

  it('refuses what it cannot place, and a document that is already migrated', () => {
    assert.throws(() => migrate([{ ...flat, mystery: 1 }]), /unrecognised field "mystery"/);
    assert.throws(() => migrate([{ chainId: 1, walletApi: {} }]), /already has per-service sections/);
    assert.throws(() => migrate({}), /must be a JSON array/);
  });
});
