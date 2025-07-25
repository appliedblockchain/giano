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



## 🔍 Android Passkey Test Results

Use `/android-passkey-test` for checking WebAuthn compatibility on your Android device.

### Test Environment
- **Device**: Android 14
- **Autofill Service**: 1Password
- **Browsers**:
  - Chrome Version: 138.0.7204.157
  - Firefox Version: 140.0.4

> **Important Note on Autofill Services**: Android autofill service settings (like 1Password) do **not** affect passkey operations. Even with 1Password set as the autofill service, 1Password will not prompt during passkey creation or retrieval. Passkey authentication is handled separately by platform authenticators (Android screen lock) or browser-specific managers (Google Password Manager), not by autofill services.

### Configuration Test Results

The table below shows which authenticator is invoked based on different `authenticatorSelection` properties:

| Configuration | Chrome Result | Firefox Result | Notes |
|--------------|---------------|----------------|-------|
| `authenticatorAttachment: 'platform'`<br/>`residentKey: 'required'`<br/>`userVerification: 'required'` | 🔵 Google Password Manager | 🟡 Screen Lock (Platform) | Chrome prefers Google PM for resident keys |
| `authenticatorAttachment: 'platform'` | 🟡 Screen Lock (Platform) | 🟡 Screen Lock (Platform) | ✅ Consistent cross-browser |
| `authenticatorAttachment: 'platform'`<br/>`userVerification: 'preferred'` | 🟡 Screen Lock (Platform) | 🟡 Screen Lock (Platform) | ✅ Consistent cross-browser |
| `authenticatorAttachment: 'platform'`<br/>`userVerification: 'discouraged'` | 🟡 Screen Lock (Platform) | 🟡 Screen Lock (Platform) | ✅ Consistent cross-browser |
| `authenticatorAttachment: 'platform'`<br/>`residentKey: 'preferred'`<br/>`userVerification: 'preferred'` | 🔵 Google Password Manager | 🟡 Screen Lock (Platform) | Chrome triggered by RK preference |
| `authenticatorAttachment: 'platform'`<br/>`residentKey: 'discouraged'`<br/>`userVerification: 'preferred'` | 🟡 Screen Lock (Platform) | 🟡 Screen Lock (Platform) | ✅ Consistent cross-browser |
| `userVerification: 'preferred'`<br/>`residentKey: 'preferred'` | 🔵 Google Password Manager | ⚠️ Intermittent behavior | Firefox menu works inconsistently |
| `authenticatorAttachment: 'cross-platform'`<br/>`userVerification: 'required'` | 🔴 External Authenticator Menu | 🔴 External Authenticator Menu | Expected behavior |
| `authenticatorAttachment: 'platform'`<br/>`requireResidentKey: false`<br/>`userVerification: 'preferred'` | 🟡 Screen Lock (Platform) | 🟡 Screen Lock (Platform) | ✅ Consistent cross-browser |
| `authenticatorAttachment: 'platform'`<br/>`userVerification: 'discouraged'`<br/>`residentKey: 'discouraged'` | 🟡 Screen Lock (Platform) | 🟡 Screen Lock (Platform) | ✅ Consistent cross-browser |

### Key Findings

#### 🔍 **Chrome Behavior**
- **Google Password Manager** is triggered when:
  - `residentKey: 'required'` OR `requireResidentKey: true`
  - `residentKey: 'preferred'` (sometimes)
- **Platform Authenticator** (screen lock) is used for most other configurations

#### 🦊 **Firefox Behavior**
- **Consistently uses Platform Authenticator** for most configurations
- **Does not invoke Google Password Manager** like Chrome for passkey creation (`credentials.create()`)
- **"Any Authenticator" configuration is problematic** - shows menu but authentication fails

> **🔍 Special Note on Firefox Authentication:** While Firefox uses System Screen Lock for passkey creation, it **can** trigger Google Password Manager for authentication (`credentials.get()`) when using `allowCredentials: []` (empty array) and `mediation: 'optional'`. This creates a potential incompatibility where passkeys created in Firefox (stored locally) cannot be accessed via the Google PM authentication flow.

#### 🎯 **Cross-Browser Compatibility**
Configurations that showed consistent behavior in both browsers on this test device:
- `authenticatorAttachment: 'platform'` + `userVerification: 'discouraged'` + `residentKey: 'discouraged'`
- `authenticatorAttachment: 'platform'` (minimal)
- `authenticatorAttachment: 'platform'` + `userVerification: 'discouraged'`
- `authenticatorAttachment: 'platform'` + `residentKey: 'discouraged'`
- `authenticatorAttachment: 'platform'` + `requireResidentKey: false`

**Note:** These results are specific to this test setup (Android 14+ with 1Password autofill service). Behavior may vary on different Android versions, devices, or configurations.

### Authenticator Types Explained

| Type | Description | When Used |
|------|-------------|-----------|
| 🟡 **Screen Lock (Platform)** | Android's built-in passkey storage using device biometric/PIN | Most configurations, consistent cross-browser |
| 🔵 **Google Password Manager** | Chrome's cloud-based passkey storage | Chrome only, when resident keys are required/preferred |
| 🔴 **External Authenticator** | Hardware security keys, other devices | When `cross-platform` is specified |

---

**⚡ Quick Start:** Run `ngrok http 4000`, then open the ngrok HTTPS URL on your Android device using Chrome browser for optimal WebAuthn support!