import { ethers } from 'hardhat';

/**
 * Example deployment and upgrade workflow for Giano Smart Wallets
 * 
 * This script demonstrates:
 * 1. Deploying V07 and V08 implementations
 * 2. Creating wallets with V07 (backward compatible)
 * 3. Upgrading individual wallets to V08 when ready
 */
async function main() {
    console.log('🚀 Giano Smart Wallet Deployment & Upgrade Example\n');
    
    const [deployer, user1, user2] = await ethers.getSigners();
    console.log('🏭 Deployer:', await deployer.getAddress());
    console.log('👤 User1:', await user1.getAddress());
    console.log('👤 User2:', await user2.getAddress());
    
    // ========================================================================================
    // PHASE 1: INITIAL DEPLOYMENT (V07 ONLY)
    // ========================================================================================
    console.log('\n🏗️  PHASE 1: Initial Deployment (V07 Implementation)\n');
    
    // Deploy V07 implementation
    console.log('📋 Deploying V07 implementation...');
    const GianoSmartWalletV07 = await ethers.getContractFactory('GianoSmartWallet');
    const v07Implementation = await GianoSmartWalletV07.deploy();
    await v07Implementation.waitForDeployment();
    console.log('✅ V07 Implementation:', await v07Implementation.getAddress());
    
    // Deploy factory with V07 implementation
    console.log('📋 Deploying factory...');
    const GianoSmartWalletFactory = await ethers.getContractFactory('GianoSmartWalletFactory');
    const factory = await GianoSmartWalletFactory.deploy(await v07Implementation.getAddress());
    await factory.waitForDeployment();
    console.log('✅ Factory:', await factory.getAddress());
    
    // Create user wallets (both use V07)
    console.log('\n👥 Creating user wallets...');
    
    // User 1 wallet
    const user1OwnerBytes = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await user1.getAddress()]);
    const user1CreateTx = await factory.connect(user1).createAccount([user1OwnerBytes], 1);
    const user1Receipt = await user1CreateTx.wait();
    const user1Event = user1Receipt?.logs.find((log: any) => {
        try { return factory.interface.parseLog(log)?.name === 'AccountCreated'; } catch { return false; }
    });
    const user1WalletAddr = factory.interface.parseLog(user1Event!)?.args.account;
    console.log('✅ User1 Wallet (V07):', user1WalletAddr);
    
    // User 2 wallet  
    const user2OwnerBytes = ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await user2.getAddress()]);
    const user2CreateTx = await factory.connect(user2).createAccount([user2OwnerBytes], 1);
    const user2Receipt = await user2CreateTx.wait();
    const user2Event = user2Receipt?.logs.find((log: any) => {
        try { return factory.interface.parseLog(log)?.name === 'AccountCreated'; } catch { return false; }
    });
    const user2WalletAddr = factory.interface.parseLog(user2Event!)?.args.account;
    console.log('✅ User2 Wallet (V07):', user2WalletAddr);
    
    // Verify both wallets use V07 EntryPoint
    const user1WalletV07 = GianoSmartWalletV07.attach(user1WalletAddr);
    const user2WalletV07 = GianoSmartWalletV07.attach(user2WalletAddr);
    
    console.log('\n🔍 Verifying V07 state...');
    console.log('User1 EntryPoint:', await user1WalletV07.entryPoint());
    console.log('User2 EntryPoint:', await user2WalletV07.entryPoint());
    
    // ========================================================================================
    // PHASE 2: V08 DEPLOYMENT (UPGRADE TARGET AVAILABLE)
    // ========================================================================================
    console.log('\n🚀 PHASE 2: V08 Implementation Available\n');
    
    // Deploy V08 implementation (upgrade target)
    console.log('📋 Deploying V08 implementation...');
    const GianoSmartWalletV08 = await ethers.getContractFactory('GianoSmartWalletV08Implementation');
    const v08Implementation = await GianoSmartWalletV08.deploy();
    await v08Implementation.waitForDeployment();
    console.log('✅ V08 Implementation:', await v08Implementation.getAddress());
    console.log('🔍 V08 EntryPoint:', await v08Implementation.entryPoint());
    
    console.log('\n📢 Both implementations now available:');
    console.log('• V07 Implementation (current):', await v07Implementation.getAddress());
    console.log('• V08 Implementation (upgrade target):', await v08Implementation.getAddress());
    console.log('• Users can upgrade when ready');
    
    // ========================================================================================
    // PHASE 3: SELECTIVE UPGRADES (USER CHOICE)
    // ========================================================================================
    console.log('\n⬆️  PHASE 3: User Chooses to Upgrade\n');
    
    console.log('Scenario: User1 wants V08 features, User2 stays on V07\n');
    
    // User1 upgrades to V08
    console.log('🔄 User1 upgrading to V08...');
    try {
        const upgradeTx = await user1WalletV07.connect(user1).upgradeToAndCall(
            await v08Implementation.getAddress(),
            '0x' // No initialization data
        );
        await upgradeTx.wait();
        console.log('✅ User1 upgrade successful!');
        
        // Verify User1 upgrade
        const user1WalletV08 = GianoSmartWalletV08.attach(user1WalletAddr);
        const user1NewEntryPoint = await user1WalletV08.entryPoint();
        const user1NewImpl = await user1WalletV08.implementation();
        
        console.log('📍 User1 wallet address (unchanged):', user1WalletAddr);
        console.log('🔄 User1 new implementation:', user1NewImpl);
        console.log('⚡ User1 new EntryPoint:', user1NewEntryPoint);
        
        // Test V08 functionality
        console.log('🧪 Testing User1 V08 functionality...');
        const testHash = await user1WalletV08.getUserOpHashWithoutChainId({
            sender: user1WalletAddr,
            nonce: 1,
            initCode: '0x',
            callData: '0x',
            accountGasLimits: '0x0000000000000000000000000000000000000000000000000000000000000000',
            preVerificationGas: 100000,
            gasFees: '0x0000000000000000000000000000000000000000000000000000000000000000',
            paymasterAndData: '0x',
            signature: '0x'
        });
        console.log('✅ User1 V08 hash calculation works!');
        
    } catch (error) {
        console.log('❌ User1 upgrade failed:', error);
    }
    
    // User2 stays on V07 (no action needed)
    console.log('\n😌 User2 staying on V07 (no upgrade needed)...');
    const user2CurrentEntryPoint = await user2WalletV07.entryPoint();
    const user2CurrentImpl = await user2WalletV07.implementation();
    
    console.log('📍 User2 wallet address:', user2WalletAddr);
    console.log('🔄 User2 implementation (unchanged):', user2CurrentImpl);
    console.log('⚡ User2 EntryPoint (unchanged):', user2CurrentEntryPoint);
    
    // ========================================================================================
    // SUMMARY
    // ========================================================================================
    console.log('\n🎯 DEPLOYMENT SUMMARY\n');
    
    console.log('📦 Deployments:');
    console.log('• Factory:', await factory.getAddress());
    console.log('• V07 Implementation:', await v07Implementation.getAddress());
    console.log('• V08 Implementation:', await v08Implementation.getAddress());
    
    console.log('\n👥 User Wallets:');
    console.log('• User1 (upgraded to V08):', user1WalletAddr);
    console.log('• User2 (staying on V07):', user2WalletAddr);
    
    console.log('\n✨ Benefits:');
    console.log('• ✅ Same wallet address throughout lifecycle');
    console.log('• ✅ Users choose when to upgrade');
    console.log('• ✅ No forced migrations');
    console.log('• ✅ Backward compatibility maintained');
    console.log('• ✅ Future-proof for V09, V10, etc.');
    
    console.log('\n🚀 Ready for production!');
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error('💥 Deployment failed:', error);
        process.exit(1);
    });