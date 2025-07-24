#!/usr/bin/env node

const http = require('http');

async function testProxy(path, data) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(data);

    const options = {
      hostname: 'localhost',
      port: 4000,
      path: path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
    };

    const req = http.request(options, (res) => {
      let responseData = '';

      res.on('data', (chunk) => {
        responseData += chunk;
      });

      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseData);
          resolve({ status: res.statusCode, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, data: responseData });
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

async function runTests() {
  console.log('🧪 Testing proxy routes...\n');

  try {
    // Test hardhat proxy
    console.log('📡 Testing hardhat proxy (/api/proxy/hardhat)...');
    const hardhatResult = await testProxy('/api/proxy/hardhat', {
      jsonrpc: '2.0',
      method: 'eth_blockNumber',
      params: [],
      id: 1
    });

    if (hardhatResult.status === 200 && hardhatResult.data.result) {
      console.log('✅ Hardhat proxy working! Block number:', hardhatResult.data.result);
    } else {
      console.log('❌ Hardhat proxy failed:', hardhatResult);
    }

    // Test bundler proxy
    console.log('\n📡 Testing bundler proxy (/api/proxy/bundler)...');
    const bundlerResult = await testProxy('/api/proxy/bundler', {
      jsonrpc: '2.0',
      method: 'eth_chainId',
      params: [],
      id: 1
    });

    if (bundlerResult.status === 200 && bundlerResult.data.result) {
      console.log('✅ Bundler proxy working! Chain ID:', bundlerResult.data.result);
    } else {
      console.log('❌ Bundler proxy failed:', bundlerResult);
    }

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.log('\n🔧 Make sure:');
    console.log('1. Next.js dev server is running on port 4000');
    console.log('2. Hardhat node is running on port 8545');
    console.log('3. Bundler service is running on port 4337');
  }

  console.log('\n📋 If tests pass, you can now use ngrok:');
  console.log('   ngrok http 4000');
  console.log('   Then test on Android using the ngrok HTTPS URL');
}

runTests();