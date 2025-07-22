# Android WebAuthn Testing Guide

## Overview

Testing WebAuthn (passkeys) on Android devices requires special setup due to HTTPS security requirements. This guide covers how to properly test your passkey implementation on Android devices.

## 🔒 HTTPS & Certificate Requirements

### Why HTTPS is Required

WebAuthn APIs are **only available in secure contexts**:
- ✅ `https://` URLs with valid certificates
- ✅ `http://localhost` (development only)
- ❌ `http://` URLs with IP addresses
- ❌ `http://` URLs with domain names
- ❌ Self-signed certificates

### Self-Signed Certificates Don't Work

❌ **Self-signed certificates are problematic on Android because:**
- Mobile browsers don't trust them by default
- Users would need to manually install certificates (complex process)
- Some Android versions/browsers reject them entirely
- **On Android, if the certificate is not trusted, `navigator.credentials` will be undefined**
- **WebAuthn operations will fail with security errors when certificates are not trusted**

### Recommended HTTPS Solutions

#### 1. **ngrok** (Recommended)
```bash
# Install ngrok: https://ngrok.com/
ngrok http 4000

# Example output:
# https://abc123.ngrok.io -> http://localhost:4000
```
**Pros:** Free tier, stable tunnels, valid SSL certificates
**Cons:** URLs change on restart (unless paid)

#### 2. **localtunnel**
```bash
npm install -g localtunnel
lt --port 4000

# Example output:
# https://random-name-123.loca.lt -> http://localhost:4000
```
**Pros:** Free, no account required
**Cons:** Less stable, frequent URL changes

## 📱 Android Requirements

For full passkey support and storage in Google Password Manager, **Android 14+** is needed.

## 🧪 Testing Setup

### 1. Proxy Configuration

The app uses proxy routes to serve all services through port 4000:

```typescript
// All services accessible via Next.js proxy routes
'/api/proxy/hardhat' → Your hardhat RPC
'/api/proxy/bundler' → Your bundler service
```

### 2. Environment Setup

Follow the setup instructions in [README.md](../../README.md), then:

```bash
# 2. Expose via tunnel
ngrok http 4000
```

### 3. Testing Workflow

```bash
# Test proxy routes
cd services/custom-example
pnpm run test-proxy

# Test Giano demo pages
# Visit these URLs via ngrok tunnel on your Android device:
# - /multiple-owners
# - /server-storage-demo
# - Other demo pages as needed
```



## 🔍 Debugging Android Issues

Use `/android-passkey-test` for checking WebAuthn compatibility on your Android device.

---

**⚡ Quick Start:** Run `ngrok http 4000`, then open the ngrok HTTPS URL on your Android device using Chrome browser for optimal WebAuthn support!