const fs = require('fs');
const path = require('path');
const assert = require('assert');

async function main() {
  const deployedAddressesPath = path.resolve(__dirname, '../../../packages/contracts/ignition/deployments/chain-31337/deployed_addresses.json');
  if (!fs.existsSync(deployedAddressesPath)) {
    throw new Error('Deployed addresses file not found');
  }

  try {
    const deployedAddresses = JSON.parse(fs.readFileSync(deployedAddressesPath, 'utf8'));

    assert(deployedAddresses['GianoAccountFactory#GianoSmartWalletFactory'], 'GianoAccountFactory#GianoSmartWalletFactory not found');
    assert(deployedAddresses['CredentialKeyMapper#CredentialKeyMapper'], 'CredentialKeyMapper#CredentialKeyMapper not found');
    assert(deployedAddresses['Testing#PermissivePaymaster'], 'Testing#PermissivePaymaster not found');
    assert(deployedAddresses['Testing#PrivateERC20'], 'Testing#PrivateERC20 not found');

    const newEnvLines = [];

    const envFilePath = path.resolve(__dirname, '../.env');
    if (fs.existsSync(envFilePath)) {
      newEnvLines.push(
          ...(await fs.promises.readFile(envFilePath, 'utf8'))
          .split('\n')
      );
      newEnvLines.push('');
      newEnvLines.push('# Addresses appended by script/append-address-env-vars.js:');
    }

    newEnvLines.push('NEXT_PUBLIC_PAYMASTER_ADDRESS=' + deployedAddresses['Testing#PermissivePaymaster']);
    newEnvLines.push('NEXT_PUBLIC_CREDENTIAL_KEY_MAPPER_ADDRESS=' + deployedAddresses['CredentialKeyMapper#CredentialKeyMapper']);
    newEnvLines.push('NEXT_PUBLIC_GIANO_SMART_WALLET_FACTORY_ADDRESS=' + deployedAddresses['GianoAccountFactory#GianoSmartWalletFactory']);
    newEnvLines.push('NEXT_PUBLIC_PRIVATE_ERC20_ADDRESS=' + deployedAddresses['Testing#PrivateERC20']);
    newEnvLines.push('');

    await fs.promises.writeFile(envFilePath, newEnvLines.join('\n'), 'utf8');
  } catch (error) {
    console.error(error);
  }
}

main();
