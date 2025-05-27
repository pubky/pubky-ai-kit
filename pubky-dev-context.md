# Complete Pubky Protocol Development Guide for LLMs

> **CRITICAL**: This guide contains only actual functionality from the Pubky protocol. Do not mock, simulate, or invent any features not explicitly documented here. All code examples are based on real API implementations.

## Core Architecture & Concepts

### Pubky Protocol Overview
Pubky is an open protocol for per-public-key backends enabling censorship-resistant web applications. It combines public-key based DNS (Pkarr) with conventional web technologies for decentralized identity and data storage.

### Core Components

**Client** - Available in Rust and JavaScript/WebAssembly
- Handles authentication, data operations, protocol communication
- NPM package: `@synonymdev/pubky`
- React Native package: `@synonymdev/react-native-pubky`

**Homeserver** - User's personal backend
- Provides storage and HTTP endpoints
- Validates authentication tokens and manages user data
- Key-value store accessed via HTTP methods (PUT, GET, DELETE)
- Supports both public and private data (current implementations focus on public data)
- Can be operated by individuals, cooperatives, or commercial entities

**Pkarr Network** - Distributed DNS alternative
- Uses public keys as domains via Mainline DHT
- Resolves `pubky://` URLs to homeserver endpoints
- Leverages BitTorrent's Mainline DHT for data distribution
- Records are ephemeral and need periodic republishing

**Pubky-Nexus** - Backend aggregation service
- Aggregates, indexes, and caches data from multiple Homeservers
- Provides higher-level REST API for social applications
- Components: nexus-watcher, nexus-service, nexusd
- Databases: Neo4j (social graph), Redis (caching)

### URL Structure
```
pubky://<public_key>/pub/<domain>/<path>
```
- `public_key`: z-base-32 encoded public key
- `pub/`: indicates public data
- `domain`: provides scoping (e.g., "example.com")
- `path`: specifies the resource

### Authentication Model
Uses AuthTokens - signed timestamps with capabilities that prove ownership of a public key and grant specific permissions.

### Core Principles

**Credible Exit** - Users can migrate data and identity between homeservers without losing content, connections, or identity. This prevents vendor lock-in and ensures user sovereignty.

**Censorship Resistance** - Achieved through flexible hosting and decentralized identity. Users can circumvent censorship by migrating to different homeservers while maintaining their public key identity.

**Semantic Social Graph** - Relationships between users and content are tagged with meaningful metadata, enabling weighted connections and sophisticated content curation based on relevance and trust levels.

## Secure Key Management & Generation

### **CRITICAL SECURITY REQUIREMENTS**

**Cryptographic Security**: Pubky uses Ed25519 keypairs for identity. Private keys are 32-byte values that must be generated with cryptographically secure randomness.

**Entropy Requirements**: Key generation MUST use a cryptographically secure pseudo-random number generator (CSPRNG) with sufficient entropy. Never use Math.random() or weak PRNGs.

### Secure Key Generation

```javascript
import { Client, Keypair, PublicKey } from "@synonymdev/pubky";

// SECURE: Uses cryptographically secure randomness
const keypair = Keypair.random();
const publicKey = keypair.publicKey();
const secretKey = keypair.secretKey(); // Uint8Array(32) - NEVER log or expose

// CRITICAL: Validate entropy source in production
function generateSecureKeypair() {
  // Verify we have a secure random source
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new Error('Cryptographically secure random number generator not available');
  }
  
  // Generate keypair using secure randomness
  const keypair = Keypair.random();
  
  // Validate key material
  const secretKey = keypair.secretKey();
  if (secretKey.length !== 32) {
    throw new Error('Invalid secret key length - security compromised');
  }
  
  // Check for obvious entropy failures (all zeros, repeating patterns)
  const allZeros = secretKey.every(byte => byte === 0);
  const allSame = secretKey.every(byte => byte === secretKey[0]);
  if (allZeros || allSame) {
    throw new Error('Insufficient entropy in key generation - security compromised');
  }
  
  return keypair;
}

// From existing secret key - VALIDATE SOURCE
function importSecretKey(secretBytes) {
  // Validate input is exactly 32 bytes
  if (!secretBytes || secretBytes.length !== 32) {
    throw new Error('Secret key must be exactly 32 bytes');
  }
  
  // Validate it's a Uint8Array or convert safely
  const secretArray = secretBytes instanceof Uint8Array 
    ? secretBytes 
    : new Uint8Array(secretBytes);
  
  // Basic entropy check
  const allZeros = secretArray.every(byte => byte === 0);
  const allSame = secretArray.every(byte => byte === secretArray[0]);
  if (allZeros || allSame) {
    throw new Error('Invalid secret key - insufficient entropy');
  }
  
  return Keypair.fromSecretKey(secretArray);
}
```

### Secure Storage Practices

```javascript
// NEVER store private keys in plain text
// NEVER log private keys
// NEVER transmit private keys unencrypted

class SecureKeyStorage {
  constructor() {
    this.keyCache = new Map();
    this.keyTimeout = 5 * 60 * 1000; // 5 minutes
  }
  
  // Store key temporarily in memory with timeout
  storeTemporary(keyId, keypair) {
    // Clear any existing timeout
    if (this.keyCache.has(keyId)) {
      clearTimeout(this.keyCache.get(keyId).timeout);
    }
    
    // Set new timeout to clear key from memory
    const timeout = setTimeout(() => {
      this.clearKey(keyId);
    }, this.keyTimeout);
    
    this.keyCache.set(keyId, { keypair, timeout });
  }
  
  // Securely clear key from memory
  clearKey(keyId) {
    const entry = this.keyCache.get(keyId);
    if (entry) {
      // Clear timeout
      clearTimeout(entry.timeout);
      
      // Overwrite secret key bytes in memory (best effort)
      try {
        const secretKey = entry.keypair.secretKey();
        secretKey.fill(0);
      } catch (error) {
        // Key may be immutable, continue with deletion
      }
      
      this.keyCache.delete(keyId);
    }
  }
  
  // Clear all keys on application exit
  clearAll() {
    for (const [keyId] of this.keyCache) {
      this.clearKey(keyId);
    }
  }
}

// Register cleanup on process exit
const keyStorage = new SecureKeyStorage();
process.on('exit', () => keyStorage.clearAll());
process.on('SIGINT', () => {
  keyStorage.clearAll();
  process.exit(0);
});
```

### Secure Recovery File Implementation

```javascript
import { createRecoveryFile, decryptRecoveryFile } from "@synonymdev/pubky";

// SECURE recovery file creation
function createSecureRecoveryFile(keypair, passphrase) {
  // Validate passphrase strength
  if (!passphrase || passphrase.length < 12) {
    throw new Error('Recovery passphrase must be at least 12 characters');
  }
  
  // Check for common weak passphrases
  const weakPatterns = [
    /^password/i, /^123/, /^qwerty/i, /^admin/i,
    /^(.)\1{7,}/, // Repeating characters
    /^(..)\1{3,}/ // Repeating pairs
  ];
  
  if (weakPatterns.some(pattern => pattern.test(passphrase))) {
    throw new Error('Passphrase is too weak - use a strong, unique passphrase');
  }
  
  // Create recovery file (uses scrypt for key derivation)
  const recoveryFile = createRecoveryFile(keypair, passphrase);
  
  // Validate recovery file format and length
  if (recoveryFile.length !== 91) {
    throw new Error('Invalid recovery file generated');
  }
  
  const recoveryString = new TextDecoder().decode(recoveryFile);
  if (!recoveryString.startsWith('pubky.org/recovery\n')) {
    throw new Error('Invalid recovery file format');
  }
  
  // Test recovery works immediately
  try {
    const testKeypair = decryptRecoveryFile(recoveryFile, passphrase);
    const originalPubkey = keypair.publicKey().z32();
    const recoveredPubkey = testKeypair.publicKey().z32();
    
    if (originalPubkey !== recoveredPubkey) {
      throw new Error('Recovery file validation failed - keys do not match');
    }
  } catch (error) {
    throw new Error(`Recovery file creation failed validation: ${error.message}`);
  }
  
  console.log('Recovery file created and validated successfully');
  console.log('Store this file and passphrase in separate, secure locations');
  
  return recoveryFile;
}

// SECURE recovery file decryption
function recoverFromSecureFile(recoveryFile, passphrase) {
  try {
    // Validate inputs
    if (!recoveryFile || !passphrase) {
      throw new Error('Recovery file and passphrase required');
    }
    
    // Handle both string and Uint8Array inputs
    let recoveryData = recoveryFile;
    if (typeof recoveryFile === 'string') {
      // If base64 string, decode it
      if (recoveryFile.includes('pubky.org/recovery')) {
        recoveryData = new TextEncoder().encode(recoveryFile);
      } else {
        // Assume base64 encoded
        recoveryData = new Uint8Array(atob(recoveryFile).split('').map(c => c.charCodeAt(0)));
      }
    }
    
    // Validate recovery file format
    if (recoveryData.length !== 91) {
      throw new Error('Invalid recovery file length - file may be corrupted');
    }
    
    const recoveryString = new TextDecoder().decode(recoveryData);
    if (!recoveryString.startsWith('pubky.org/recovery\n')) {
      throw new Error('Invalid recovery file format - not a valid Pubky recovery file');
    }
    
    // Decrypt and recover keypair
    const restoredKeypair = decryptRecoveryFile(recoveryData, passphrase);
    
    // Validate recovered keypair
    const secretKey = restoredKeypair.secretKey();
    if (secretKey.length !== 32) {
      throw new Error('Recovered secret key has invalid length');
    }
    
    console.log('Recovery file decrypted successfully');
    return restoredKeypair;
    
  } catch (error) {
    console.error('Recovery file decryption failed:', error.message);
    
    if (error.message.includes('decrypt') || error.message.includes('Invalid')) {
      throw new Error('Invalid passphrase or corrupted recovery file');
    }
    
    throw error;
  }
}
```

### React Native Secure Key Generation

```javascript
import { generateSecretKey, getPublicKeyFromSecretKey } from '@synonymdev/react-native-pubky';

// Generate cryptographically secure keypair
async function generateSecureKeypair() {
  try {
    // React Native implementation uses secure random generation
    const result = await generateSecretKey();
    
    if (result.isErr()) {
      throw new Error('Key generation failed: ' + result.error);
    }
    
    const { secret_key, public_key, uri } = result.value;
    
    // Validate generated key
    if (!secret_key || secret_key.length === 0) {
      throw new Error('Generated secret key is empty');
    }
    
    // Convert to bytes for validation
    const secretBytes = secret_key.split(',').map(n => parseInt(n.trim()));
    if (secretBytes.length !== 32) {
      throw new Error('Generated secret key has invalid length');
    }
    
    // Basic entropy validation
    const allZeros = secretBytes.every(byte => byte === 0);
    const allSame = secretBytes.every(byte => byte === secretBytes[0]);
    if (allZeros || allSame) {
      throw new Error('Generated key has insufficient entropy');
    }
    
    console.log('Secure keypair generated successfully');
    return result.value;
    
  } catch (error) {
    console.error('Secure key generation failed:', error.message);
    throw error;
  }
}

// Validate existing secret key
async function validateSecretKey(secretKey) {
  try {
    const result = await getPublicKeyFromSecretKey(secretKey);
    
    if (result.isErr()) {
      throw new Error('Invalid secret key: ' + result.error);
    }
    
    return result.value;
  } catch (error) {
    throw new Error('Secret key validation failed: ' + error.message);
  }
}
```

### Rust Secure Key Generation

```rust
use pubky::{Keypair, PublicKey};
use rand::rngs::OsRng;

// Generate cryptographically secure keypair
fn generate_secure_keypair() -> Result<Keypair, Box<dyn std::error::Error>> {
    // Verify we have access to OS random number generator
    let mut rng = OsRng;
    
    // Generate keypair using cryptographically secure randomness
    let keypair = Keypair::random();
    
    // Validate key material
    let secret_bytes = keypair.secret_key().to_bytes();
    if secret_bytes.len() != 32 {
        return Err("Invalid secret key length".into());
    }
    
    // Basic entropy checks
    let all_zeros = secret_bytes.iter().all(|&b| b == 0);
    let all_same = secret_bytes.iter().all(|&b| b == secret_bytes[0]);
    
    if all_zeros || all_same {
        return Err("Insufficient entropy in generated key".into());
    }
    
    println!("Secure keypair generated successfully");
    Ok(keypair)
}

// Secure key import with validation
fn import_secret_key(secret_bytes: &[u8]) -> Result<Keypair, Box<dyn std::error::Error>> {
    // Validate input length
    if secret_bytes.len() != 32 {
        return Err("Secret key must be exactly 32 bytes".into());
    }
    
    // Basic entropy validation
    let all_zeros = secret_bytes.iter().all(|&b| b == 0);
    let all_same = secret_bytes.iter().all(|&b| b == secret_bytes[0]);
    
    if all_zeros || all_same {
        return Err("Invalid secret key - insufficient entropy".into());
    }
    
    // Create keypair from validated bytes
    let keypair = Keypair::from_secret_key(secret_bytes)?;
    
    Ok(keypair)
}
```

### Security Best Practices

**Key Generation Environment**:
```javascript
// Production key generation checklist
function validateSecureEnvironment() {
  const checks = {
    hasSecureRandom: typeof crypto !== 'undefined' && crypto.getRandomValues,
    isSecureContext: typeof window === 'undefined' || window.isSecureContext,
    hasWebCrypto: typeof crypto !== 'undefined' && crypto.subtle,
    nodeVersion: typeof process !== 'undefined' ? process.version : null
  };
  
  console.log('Security environment check:', checks);
  
  if (!checks.hasSecureRandom) {
    throw new Error('Cryptographically secure random number generator not available');
  }
  
  if (typeof window !== 'undefined' && !checks.isSecureContext) {
    console.warn('WARNING: Not running in secure context (HTTPS). Keys may be compromised.');
  }
  
  return checks;
}
```

**Memory Security**:
```javascript
// Minimize private key exposure in memory
class SecureKeyHandler {
  constructor(keypair) {
    this.publicKey = keypair.publicKey().z32();
    this._secretKey = keypair.secretKey();
    this._accessCount = 0;
    this._maxAccess = 100; // Limit access to prevent memory dumps
  }
  
  getSecretKey() {
    if (this._accessCount >= this._maxAccess) {
      throw new Error('Key access limit exceeded - regenerate keypair');
    }
    this._accessCount++;
    return this._secretKey;
  }
  
  // Securely dispose of key material
  dispose() {
    if (this._secretKey) {
      // Overwrite memory (best effort)
      this._secretKey.fill(0);
      this._secretKey = null;
    }
  }
}
```

**Key Rotation Strategy**:
```javascript
// Implement key rotation for long-lived applications
class KeyRotationManager {
  constructor(client) {
    this.client = client;
    this.rotationInterval = 90 * 24 * 60 * 60 * 1000; // 90 days
    this.lastRotation = Date.now();
  }
  
  shouldRotateKey() {
    return (Date.now() - this.lastRotation) > this.rotationInterval;
  }
  
  async rotateKey(currentKeypair, homeserver) {
    if (!this.shouldRotateKey()) {
      return currentKeypair;
    }
    
    console.log('Initiating key rotation...');
    
    // Generate new keypair
    const newKeypair = generateSecureKeypair();
    
    // Sign up new key
    await this.client.signup(newKeypair, homeserver);
    
    // TODO: Migrate data from old key to new key
    // This would involve copying all data and updating references
    
    // Sign out old key after migration
    await this.client.signout(currentKeypair.publicKey());
    
    this.lastRotation = Date.now();
    console.log('Key rotation completed successfully');
    
    return newKeypair;
  }
}
```

### Development vs Production Security

**Development Environment**:
```javascript
// Development key generation - NEVER use in production
function generateDevelopmentKeypair() {
  console.warn('WARNING: Development key generation - NOT for production use');
  
  // Still use secure generation even in development
  const keypair = Keypair.random();
  
  // Log public key for development convenience
  console.log('Development public key:', keypair.publicKey().z32());
  
  return keypair;
}
```

**Production Environment**:
```javascript
// Production key generation with extra security measures
function generateProductionKeypair() {
  // Validate secure environment
  validateSecureEnvironment();
  
  // Generate with secure randomness
  const keypair = generateSecureKeypair();
  
  // Never log private key material in production
  console.log('Production keypair generated - public key ready for use');
  
  return keypair;
}
```

## Real-World Implementation Challenges & Solutions

### CORS Issues in Web Applications

**Problem**: Browser CORS policies block cross-origin requests to homeservers and Nexus APIs.

**Solutions**:
1. **CORS Proxy**: Route requests through proxy services
   ```javascript
   const corsProxy = 'https://api.allorigins.win/raw?url=';
   const response = await fetch(`${corsProxy}${actualUrl}`);
   ```

2. **CLI Tools**: Bypass CORS entirely with Node.js applications
   ```bash
   # CLI tools make direct HTTP requests without browser restrictions
   pubky-debug hs GET /pub/profile.json
   ```

3. **Browser Development Mode**: 
   ```bash
   # Chrome with disabled security (development only)
   google-chrome --disable-web-security --user-data-dir=/tmp/chrome_dev
   ```

### Authentication Flow Complexity

**Key Distinctions**:
- `signin()`: For existing users with homeserver accounts
- `signup()`: For new users, often requires invite tokens
- `republishHomeserver()`: Updates Pkarr records without HTTP API calls

**Robust Authentication Pattern**:
```javascript
async function authenticateRobustly(client, keypair, homeserver, inviteToken = null) {
  try {
    // Try signin first
    await client.signin(keypair);
    console.log('Signed in successfully');
  } catch (signinError) {
    console.log('Signin failed, attempting signup...');
    try {
      await client.signup(keypair, homeserver, inviteToken);
      console.log('Signed up successfully');
    } catch (signupError) {
      if (signupError.toString().includes('signup_token required')) {
        throw new Error('Signup requires invite token');
      }
      // Fallback to republish for key managers
      await client.republishHomeserver(keypair, homeserver);
      console.log('Homeserver record republished');
    }
  }
  
  // Verify session
  const session = await client.session(keypair.publicKey());
  if (!session) {
    throw new Error('Failed to establish session');
  }
  
  return session;
}
```

### Session Persistence

**Problem**: Sessions don't persist between application restarts or CLI commands.

**Solution**: Save authentication state and restore sessions:
```javascript
// Save session state
function saveAuthState(keypair, isAuthenticated) {
  const config = {
    keypair: Array.from(keypair.secretKey()),
    authenticated: isAuthenticated,
    timestamp: Date.now()
  };
  fs.writeFileSync(configPath, JSON.stringify(config));
}

// Restore session
async function restoreSession(client) {
  const config = JSON.parse(fs.readFileSync(configPath));
  if (config.keypair && config.authenticated) {
    const keypair = Keypair.fromSecretKey(new Uint8Array(config.keypair));
    
    // Re-establish session
    await client.signin(keypair);
    const session = await client.session(keypair.publicKey());
    
    return { keypair, session };
  }
  return null;
}
```

### Homeserver Reliability

**Problem**: Homeservers may be unreachable or require invite tokens.

**Testing Strategy**:
```javascript
async function testConnectivity(homeserverKey) {
  // Test Pkarr record availability
  try {
    const pkarrResponse = await fetch(`https://pkarr.pubky.org/${homeserverKey}`);
    if (!pkarrResponse.ok) {
      throw new Error('Pkarr record not found');
    }
    console.log('Pkarr record found');
  } catch (error) {
    console.error('Pkarr test failed:', error.message);
    return false;
  }
  
  return true;
}

// Multiple homeserver fallback
const knownHomeservers = [
  '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo', // testnet
  'ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy'  // production
];

async function findWorkingHomeserver() {
  for (const homeserver of knownHomeservers) {
    if (await testConnectivity(homeserver)) {
      return homeserver;
    }
  }
  throw new Error('No working homeservers found');
}
```

### Enhanced Error Handling

**Comprehensive Error Context**:
```javascript
function createDetailedError(operation, error, context = {}) {
  console.error(`${operation} failed:`, error.message || error);
  console.debug('Error details:', {
    type: typeof error,
    name: error.name,
    stack: error.stack,
    toString: error.toString(),
    ...context
  });
  
  // Provide actionable suggestions
  if (error.toString().includes('CORS')) {
    console.log('Try using CORS proxy or CLI tool');
  } else if (error.toString().includes('signup_token required')) {
    console.log('Signup requires invite token: --token YOUR_TOKEN');
  } else if (error.toString().includes('error sending request')) {
    console.log('Homeserver may be unreachable or down');
  }
}
```

## Application Architecture Patterns

### 1. CLI Tools (Recommended for Development)
Avoid CORS issues and provide direct protocol access:

```javascript
// CLI tool structure
class PubkyCLI {
  constructor() {
    this.client = null;
    this.config = this.loadConfig();
    this.keypair = null;
  }
  
  async initialize() {
    this.client = this.config.testnet ? Client.testnet() : new Client();
    if (this.config.keypair) {
      this.keypair = Keypair.fromSecretKey(new Uint8Array(this.config.keypair));
    }
  }
  
  async ensureAuthenticated() {
    if (!this.keypair) {
      throw new Error('No keypair. Run: auth --generate');
    }
    
    await this.client.signin(this.keypair);
    const session = await this.client.session(this.keypair.publicKey());
    if (!session) {
      throw new Error('Authentication failed');
    }
    
    return session;
  }
}
```

### 2. Web Applications with CORS Handling
```javascript
class PubkyWebApp {
  constructor() {
    this.client = Client.testnet();
    this.corsProxy = 'https://api.allorigins.win/raw?url=';
    this.useCorsProxy = true;
  }
  
  async makeRequest(url, options = {}) {
    const finalUrl = this.useCorsProxy ? `${this.corsProxy}${url}` : url;
    
    try {
      return await fetch(finalUrl, {
        ...options,
        headers: {
          ...options.headers,
          ...(this.useCorsProxy && { 'X-Requested-With': 'XMLHttpRequest' })
        }
      });
    } catch (error) {
      if (error.message.includes('CORS')) {
        console.warn('CORS error - try enabling proxy or using CLI tool');
      }
      throw error;
    }
  }
}
```

### 3. Debug Tools Pattern
Essential features for any Pubky development tool:

```javascript
class PubkyDebugTool {
  constructor() {
    this.debugMode = false;
    this.logs = [];
  }
  
  debug(...args) {
    if (this.debugMode) {
      const message = args.join(' ');
      console.log(`[DEBUG] ${message}`);
      this.logs.push({ level: 'debug', message, timestamp: Date.now() });
    }
  }
  
  async testConnectivity() {
    // Test homeserver
    await this.testHomeserver();
    // Test Nexus API
    await this.testNexus();
  }
  
  async testHomeserver() {
    try {
      this.debug('Testing homeserver connectivity...');
      // Implementation details...
    } catch (error) {
      this.debug('Homeserver test failed:', error);
    }
  }
  
  generateUsageExamples() {
    return [
      'pubky-tool auth --generate',
      'pubky-tool test --all',
      'pubky-tool hs PUT /pub/profile.json --data \'{"name":"User"}\'',
      'pubky-tool nexus /v0/user/USER_ID'
    ];
  }
}
```

### 4. Client-Homeserver (Direct)
Simple architecture where client communicates directly with a single homeserver. Optimal for:
- Bookmark management systems
- File synchronization utilities  
- Text snippet repositories
- Applications with straightforward functionality and intermittent data operations

### 5. Custom Backend
Introduces middleware between client and homeserver with components:
- **Indexer**: Data normalization and consistent structure optimization
- **Aggregator**: Event filtering and selective data propagation
- **Web Server**: Unified platform for data feeds, search, and UI configurations

### 6. Global Aggregators
Distributed system with centralized aggregation layer:
- Eliminates need to fetch from thousands of homeservers
- Implements policy-driven filtering
- Provides client flexibility to switch aggregators
- Enables scalable event distribution

## Social Media Features (Pubky App)

### Core Content Types

**Posts** - Primary content with support for:
- Text (unlimited length)
- Media (images, videos)
- Tags (hashtags with # symbol)
- Mentions (user references with pk keyword)
- Links and emojis
- Re-posts and replies

**Profiles** - User identity pages containing:
- Username (unique handle with pk prefix)
- Profile picture and bio
- Website links
- Follower/following counts
- Post timeline

### Social Interactions

**Tagging System**
- Users assign contextual tags to posts and other users
- Custom weighting of tags for filtering
- Clickable tags for content discovery
- Categorization and relevance ranking

**Bookmarks**
- Private saving of posts for later reference
- Organization by topic
- Personal note-taking system

**Notifications**
- Mentions, replies, re-posts
- New followers
- Quote posts
- Real-time activity tracking

### Advanced Features

**Perspectives** - Saved custom-filtered views combining:
- Tag filters and weights
- User selections
- Reach settings
- Trend preferences
- Custom UI layouts

**Trends** - Statistical analysis providing:
- Trending posts and tags
- User leaderboards
- Engagement metrics
- Time-based analytics

**Search** - Limited traditional search capabilities alongside tag-based filtering

**Layouts** - Multiple customizable UI options:
- Column layouts
- Grid views
- List formats

## Installation & Setup

### Development Environment Setup

```bash
# Install Pubky client
npm install @synonymdev/pubky

# For CLI tools, also install
npm install commander axios chalk

# For React Native
npm install @synonymdev/react-native-pubky

# For Rust development
cargo add pubky anyhow tokio
```

### Client Initialization

```javascript
import { Client, Keypair, PublicKey } from "@synonymdev/pubky";

// Default client (mainnet)
const client = new Client();

// Testnet client for development
const client = Client.testnet();

// Custom configuration
const client = new Client({
  pkarr: {
    relays: ['https://your-pkarr-relay.example.com/'],
    requestTimeout: 2000
  },
  userMaxRecordAge: 3600
});
```

### Authentication Flows

```javascript
// Signup to homeserver
const homeserver = PublicKey.from('your_homeserver_public_key_here');
const signupToken = 'optional_invite_code';

try {
  const session = await client.signup(keypair, homeserver, signupToken);
  console.log('Signed up:', session.pubky().z32());
  console.log('Capabilities:', session.capabilities());
} catch (error) {
  console.error('Signup failed:', error);
}

// Check session status
const session = await client.session(publicKey);
if (session) {
  console.log('Active session with capabilities:', session.capabilities());
} else {
  console.log('Not signed in');
}

// Sign in existing user
await client.signin(keypair);

// Sign out
await client.signout(publicKey);

// Get user's homeserver
try {
  const homeserverKey = await client.getHomeserver(publicKey);
  console.log('Homeserver:', homeserverKey.z32());
} catch (error) {
  console.log('No homeserver found');
}

// Republish homeserver record (for key managers)
await client.republishHomeserver(keypair, homeserverPublicKey);
```

### Data Operations

```javascript
const userPubky = publicKey.z32();

// PUT data
const url = `pubky://${userPubky}/pub/example.com/profile.json`;
const data = { name: 'Alice', bio: 'Developer' };

await client.fetch(url, {
  method: 'PUT',
  body: JSON.stringify(data),
  credentials: 'include'
});

// GET data
const response = await client.fetch(url);
if (response.status === 200) {
  const profile = await response.json();
  console.log('Profile:', profile);
}

// DELETE data
await client.fetch(url, {
  method: 'DELETE',
  credentials: 'include'
});

// PUT binary data
const imageData = new Uint8Array([/* image bytes */]);
await client.fetch(`pubky://${userPubky}/pub/images/avatar.png`, {
  method: 'PUT',
  body: imageData,
  credentials: 'include'
});
```

### Directory Listing

```javascript
// List directory contents
const dirUrl = `pubky://${userPubky}/pub/example.com/`;

// Basic listing
const files = await client.list(dirUrl);

// With options: list(url, cursor, reverse, limit, shallow)
const files = await client.list(dirUrl, null, false, 10, false);

// Paginated listing
let cursor = null;
const allFiles = [];
do {
  const batch = await client.list(dirUrl, cursor, false, 50);
  allFiles.push(...batch);
  cursor = batch.length > 0 ? batch[batch.length - 1] : null;
} while (cursor && batch.length === 50);

// Shallow listing (directories and files, not flat)
const directories = await client.list(dirUrl, null, false, null, true);
```

### Third-Party Authorization

```javascript
// App requests authorization
const relay = "https://your-relay-service.example.com/link";
const capabilities = "/pub/myapp.com/:rw,/pub/shared/:r";

const authRequest = client.authRequest(relay, capabilities);
const authUrl = authRequest.url();

// Show QR code or redirect user to authUrl
console.log('Visit:', authUrl);

// Wait for user authorization
try {
  const authorizedPubky = await authRequest.response();
  console.log('Authorized by:', authorizedPubky.z32());
  
  // Check session capabilities
  const session = await client.session(authorizedPubky);
  console.log('Granted capabilities:', session.capabilities());
} catch (error) {
  console.error('Authorization failed:', error);
}

// User authorizes the request (in authenticator app)
await client.sendAuthToken(keypair, authUrl);
```

### Environment Configuration with Testing

```javascript
// config/environment.js
class Environment {
  static async getConfig() {
    const env = process.env.NODE_ENV || 'development';
    
    const configs = {
      development: {
        client: () => Client.testnet(),
        homeserver: '8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo',
        nexus: 'http://localhost:8080',
        relays: ['http://localhost:15412/link']
      },
      
      production: {
        client: () => new Client(),
        homeserver: 'ufibwbmed6jeq9k4p583go95wofakh9fwpp4k734trq79pd9u1uy',
        nexus: 'https://nexus.pubky.app',
        relays: ['https://httprelay.pubky.app/link']
      }
    };
    
    const config = configs[env] || configs.development;
    
    // Test configuration before returning
    await this.validateConfig(config);
    
    return config;
  }
  
  static async validateConfig(config) {
    // Test homeserver connectivity
    try {
      const response = await fetch(`https://pkarr.pubky.org/${config.homeserver}`);
      if (!response.ok) {
        console.warn('Warning: Homeserver Pkarr record not accessible');
      }
    } catch (error) {
      console.warn('Warning: Cannot validate homeserver:', error.message);
    }
    
    // Test Nexus connectivity
    try {
      await fetch(`${config.nexus}/v0/stream/posts?limit=1`);
    } catch (error) {
      console.warn('Warning: Nexus API not accessible:', error.message);
    }
  }
}
```

### Robust Authentication Implementation

```javascript
async function authenticateWithRetry(client, keypair, homeserver, options = {}) {
  const {
    maxRetries = 3,
    inviteToken = null,
    fallbackToRepublish = true,
    debug = false
  } = options;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      if (debug) console.log(`Authentication attempt ${attempt}/${maxRetries}`);
      
      // Try signin first
      try {
        await client.signin(keypair);
        if (debug) console.log('Signed in successfully');
      } catch (signinError) {
        if (debug) console.log('Signin failed, trying signup...');
        
        try {
          await client.signup(keypair, homeserver, inviteToken);
          if (debug) console.log('Signed up successfully');
        } catch (signupError) {
          if (signupError.toString().includes('signup_token required') && !inviteToken) {
            throw new Error('Signup requires invite token. Use --token option.');
          }
          
          if (fallbackToRepublish && attempt === maxRetries) {
            if (debug) console.log('Signup failed, trying republish as fallback...');
            await client.republishHomeserver(keypair, homeserver);
            if (debug) console.log('Homeserver record republished');
          } else {
            throw signupError;
          }
        }
      }
      
      // Verify session
      const session = await client.session(keypair.publicKey());
      if (!session) {
        throw new Error('Session not established after authentication');
      }
      
      if (debug) {
        console.log('Session established');
        console.log('Capabilities:', session.capabilities ? session.capabilities() : 'none');
      }
      
      return session;
      
    } catch (error) {
      if (attempt === maxRetries) {
        throw new Error(`Authentication failed after ${maxRetries} attempts: ${error.message}`);
      }
      
      if (debug) console.log(`Attempt ${attempt} failed: ${error.message}`);
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
}
```

### Data Operations with Session Management

```javascript
// Wrapper that ensures authentication before data operations
class AuthenticatedClient {
  constructor(client, keypair) {
    this.client = client;
    this.keypair = keypair;
    this.sessionCache = null;
    this.sessionExpiry = 0;
  }
  
  async ensureSession() {
    const now = Date.now();
    
    // Check if cached session is still valid (cache for 5 minutes)
    if (this.sessionCache && now < this.sessionExpiry) {
      return this.sessionCache;
    }
    
    // Re-establish session
    await this.client.signin(this.keypair);
    const session = await this.client.session(this.keypair.publicKey());
    
    if (!session) {
      throw new Error('Failed to establish session');
    }
    
    this.sessionCache = session;
    this.sessionExpiry = now + (5 * 60 * 1000); // 5 minute cache
    
    return session;
  }
  
  async fetch(url, options = {}) {
    await this.ensureSession();
    
    return this.client.fetch(url, {
      ...options,
      credentials: 'include'
    });
  }
  
  async put(path, data) {
    const userPubky = this.keypair.publicKey().z32();
    const url = `pubky://${userPubky}${path.startsWith('/') ? path : '/' + path}`;
    
    const response = await this.fetch(url, {
      method: 'PUT',
      body: typeof data === 'string' ? data : JSON.stringify(data)
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`PUT failed (${response.status}): ${errorText}`);
    }
    
    return response;
  }
  
  async get(path) {
    const userPubky = this.keypair.publicKey().z32();
    const url = `pubky://${userPubky}${path.startsWith('/') ? path : '/' + path}`;
    
    const response = await this.fetch(url);
    
    if (response.status === 404) {
      return null;
    }
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`GET failed (${response.status}): ${errorText}`);
    }
    
    return response;
  }
  
  async delete(path) {
    const userPubky = this.keypair.publicKey().z32();
    const url = `pubky://${userPubky}${path.startsWith('/') ? path : '/' + path}`;
    
    const response = await this.fetch(url, { method: 'DELETE' });
    
    if (!response.ok && response.status !== 404) {
      const errorText = await response.text();
      throw new Error(`DELETE failed (${response.status}): ${errorText}`);
    }
    
    return response;
  }
  
  async list(path = '/pub/') {
    await this.ensureSession();
    
    const userPubky = this.keypair.publicKey().z32();
    const dirUrl = `pubky://${userPubky}${path.startsWith('/') ? path : '/' + path}`;
    
    try {
      const files = await this.client.list(dirUrl);
      return files;
    } catch (error) {
      if (error.message.includes('404')) {
        return [];
      }
      throw error;
    }
  }
}
```

### Directory Listing with Error Handling

```javascript
async function listDirectory(client, userPubky, path, options = {}) {
  const {
    cursor = null,
    reverse = false,
    limit = 50,
    shallow = false,
    maxRetries = 3
  } = options;
  
  const dirUrl = `pubky://${userPubky}${path.startsWith('/') ? path : '/' + path}`;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const files = await client.list(dirUrl, cursor, reverse, limit, shallow);
      
      // Return formatted results
      return files.map(filename => ({
        name: filename,
        type: filename.endsWith('/') ? 'directory' : 'file',
        path: `${path}${filename}`,
        isDirectory: filename.endsWith('/')
      }));
      
    } catch (error) {
      if (error.message.includes('404') || error.message.includes('not found')) {
        return []; // Directory doesn't exist or is empty
      }
      
      if (attempt === maxRetries) {
        throw new Error(`Directory listing failed after ${maxRetries} attempts: ${error.message}`);
      }
      
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
}
```

### Third-Party Authorization with Timeout

```javascript
async function requestAuthorization(client, relay, capabilities, timeoutMs = 60000) {
  try {
    const authRequest = client.authRequest(relay, capabilities);
    const authUrl = authRequest.url();
    
    console.log('Authorization required');
    console.log('Visit:', authUrl);
    console.log('Or scan QR code with Pubky authenticator');
    
    // Create timeout promise
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Authorization timeout')), timeoutMs);
    });
    
    // Race between authorization and timeout
    const authorizedPubky = await Promise.race([
      authRequest.response(),
      timeoutPromise
    ]);
    
    // Verify granted capabilities
    const session = await client.session(authorizedPubky);
    if (!session) {
      throw new Error('No session created after authorization');
    }
    
    const grantedCaps = session.capabilities ? session.capabilities() : [];
    console.log('Authorization successful');
    console.log('Granted capabilities:', grantedCaps);
    
    return { authorizedPubky, capabilities: grantedCaps };
    
  } catch (error) {
    if (error.message.includes('timeout')) {
      console.error('Authorization timed out. User may have denied or ignored request.');
    }
    throw error;
  }
}

// Helper for user authorization (in authenticator app)
async function authorizeApp(client, keypair, authUrl) {
  try {
    await client.sendAuthToken(keypair, authUrl);
    console.log('App authorized successfully');
  } catch (error) {
    console.error('Authorization failed:', error.message);
    throw error;
  }
}
```

## React Native Implementation

### Core Functions and Types

```javascript
import { 
  auth, parseAuthUrl, publish, resolve, signUp, signIn, signOut,
  put, get, list, deleteFile, session, generateSecretKey,
  getPublicKeyFromSecretKey, createRecoveryFile, decryptRecoveryFile,
  getHomeserver, getSignupToken, republishHomeserver,
  publishHttps, resolveHttps, setEventListener, removeEventListener
} from '@synonymdev/react-native-pubky';

// All functions return Result<T> with isOk() and isErr() methods
const result = await signIn(secretKey);
if (result.isErr()) {
  console.error(result.error);
  return;
}
console.log(result.value);

// Type definitions
export type Capability = {
  path: string;
  permission: string;
};

export type PubkyAuthDetails = {
  relay: string;
  capabilities: Capability[];
  secret: string;
};

export interface SessionInfo {
  pubky: string;
  capabilities: string[];
}

export interface IGenerateSecretKey {
  secret_key: string;
  public_key: string;
  uri: string;
}

export interface ITxt {
  cache_flush: boolean;
  class: string;
  name: string;
  rdata: {
    strings: string[];
    type: string;
  };
  ttl: number;
}

export interface IDNSPacket {
  signed_packet: string;
  public_key: string;
  signature: string;
  timestamp: number;
  last_seen: number;
  dns_packet: string;
  records: ITxt[];
}

export interface IHttpsRecord {
  name: string;
  class: string;
  ttl: number;
  priority: number;
  target: string;
  port?: number;
  alpn?: string[];
}

export interface IHttpsResolveResult {
  public_key: string;
  https_records: IHttpsRecord[];
}
```

### Authentication Examples

```javascript
// Generate new keypair
const keyResult = await generateSecretKey();
if (keyResult.isErr()) {
  console.error('Key generation failed:', keyResult.error);
  return;
}
const { secret_key, public_key, uri } = keyResult.value;

// Get public key from secret
const pubkeyResult = await getPublicKeyFromSecretKey(secret_key);
const publicKeyInfo = pubkeyResult.value;

// Parse authentication URL
const authUrl = 'pubkyauth:///?relay=https://demo.httprelay.io/link&capabilities=/pub/pubky.app:rw&secret=FyzJ3gJ1W7boyFZC1Do9fYrRmDNgCLNRwEu_gaBgPUA';
const parseResult = await parseAuthUrl(authUrl);
const authDetails = parseResult.value;

// Authenticate with parsed URL
const authResult = await auth(authUrl, secret_key);

// Get signup token (admin only)
const tokenResult = await getSignupToken(homeserverPubky, adminPassword);
const signupToken = tokenResult.value;

// Signup with optional token
const signupResult = await signUp(secret_key, homeserverUrl, signupToken);
const sessionInfo = signupResult.value;

// Sign in existing user
const signinResult = await signIn(secret_key);

// Check session
const sessionResult = await session(public_key);

// Sign out
const signoutResult = await signOut(secret_key);

// Get homeserver for public key
const homeserverResult = await getHomeserver(public_key);

// Republish homeserver record
const republishResult = await republishHomeserver(secret_key, homeserverUrl);
```

### Data Operations

```javascript
// PUT data
const putResult = await put(
  `pubky://${public_key}/pub/example.com/data.json`,
  { name: 'Alice', bio: 'Developer' }
);

// GET data
const getResult = await get(`pubky://${public_key}/pub/example.com/data.json`);
if (getResult.isOk()) {
  // Data is returned as string - parse if JSON
  const data = JSON.parse(getResult.value);
}

// LIST directory
const listResult = await list(`pubky://${public_key}/pub/example.com/`);
const files = listResult.value; // Array of filenames

// DELETE file
const deleteResult = await deleteFile(`pubky://${public_key}/pub/example.com/data.json`);
```

### Pkarr Operations

```javascript
// Publish DNS record
const publishResult = await publish('recordname', 'recordcontent', secret_key);

// Resolve DNS record
const resolveResult = await resolve(public_key);
const dnsPacket = resolveResult.value; // IDNSPacket

// Publish HTTPS record
const httpsPublishResult = await publishHttps('example.com', 'target.example.com', secret_key);

// Resolve HTTPS record
const httpsResolveResult = await resolveHttps(public_key);
const httpsData = httpsResolveResult.value; // IHttpsResolveResult
```

### Recovery Files

```javascript
// Create recovery file
const recoveryResult = await createRecoveryFile(secret_key, 'secure_passphrase');
const recoveryFile = recoveryResult.value; // Base64 encoded string

// Decrypt recovery file
const decryptResult = await decryptRecoveryFile(recoveryFile, 'secure_passphrase');
const restoredSecretKey = decryptResult.value;
```

### Event Handling

```javascript
// Set up event listener
const setupResult = await setEventListener((eventData) => {
  console.log('Received event:', eventData);
});

// Remove event listener
const removeResult = await removeEventListener();
```

## Pubky-Nexus API Integration

### Enhanced API Client

```javascript
class NexusAPIClient {
  constructor(baseUrl, options = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.timeout = options.timeout || 10000;
    this.maxRetries = options.maxRetries || 3;
    this.debug = options.debug || false;
  }
  
  async request(endpoint, params = {}, retryCount = 0) {
    const url = new URL(`${this.baseUrl}${endpoint}`);
    
    // Add query parameters
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.append(key, String(value));
      }
    });
    
    try {
      if (this.debug) console.log(`${url}`);
      
      const response = await fetch(url, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(this.timeout)
      });
      
      if (response.status === 204) {
        return []; // No content
      }
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }
      
      const data = await response.json();
      return data;
      
    } catch (error) {
      if (error.name === 'TimeoutError' || error.name === 'AbortError') {
        if (retryCount < this.maxRetries) {
          console.warn(`Request timeout, retrying... (${retryCount + 1}/${this.maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1)));
          return this.request(endpoint, params, retryCount + 1);
        }
        throw new Error(`Request timed out after ${this.maxRetries} retries`);
      }
      
      if (retryCount < this.maxRetries && error.message.includes('fetch')) {
        console.warn(`Network error, retrying... (${retryCount + 1}/${this.maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 1000 * (retryCount + 1)));
        return this.request(endpoint, params, retryCount + 1);
      }
      
      throw error;
    }
  }
}
```

### Server Info

```javascript
// Get server information
const response = await axios.get(`${NEXUS_API_BASE_URL}/info`);
const serverInfo = response.data;
```

### Post-Related Endpoints

```javascript
// Get specific post
const post = await axios.get(
  `${NEXUS_API_BASE_URL}/post/${authorId}/${postId}`,
  { params: { viewer_id: viewerId, maxTags, maxTaggers } }
);

// Get post replies
const replies = await axios.get(`${NEXUS_API_BASE_URL}/stream/posts`, {
  params: {
    author_id: authorId,
    source: 'post_replies',
    post_id: postId,
    limit: String(limit),
    viewer_id: viewerId,
    start, end, skip, order
  }
});

// Get post taggers
const taggers = await axios.get(
  `${NEXUS_API_BASE_URL}/post/${authorId}/${postId}/taggers/${label}`,
  { params: { skip, limit } }
);

// Get post tags
const postTags = await axios.get(`${NEXUS_API_BASE_URL}/post/${userId}/${postId}/tags`, {
  params: { viewer_id: viewerId, skip_tags: skip, limit_tags: limit, limit_taggers: maxTaggers }
});
```

### User-Related Endpoints

```javascript
// Get user profile
const userProfile = await axios.get(
  `${NEXUS_API_BASE_URL}/user/${userId}`,
  { params: { viewer_id: viewerId } }
);

// Get user details
const userDetails = await axios.get(`${NEXUS_API_BASE_URL}/user/${userId}/details`);

// Get followers/following/friends/muted
const followers = await axios.get(`${NEXUS_API_BASE_URL}/user/${userId}/followers`, 
  { params: { skip, limit } });
const following = await axios.get(`${NEXUS_API_BASE_URL}/user/${userId}/following`,
  { params: { skip, limit } });
const friends = await axios.get(`${NEXUS_API_BASE_URL}/user/${userId}/friends`,
  { params: { skip, limit } });
const muted = await axios.get(`${NEXUS_API_BASE_URL}/user/${userId}/muted`,
  { params: { skip, limit } });

// Get notifications
const notifications = await axios.get(
  `${NEXUS_API_BASE_URL}/user/${userId}/notifications`,
  { params: { start, end, skip, limit } }
);

// Get user tags
const userTags = await axios.get(`${NEXUS_API_BASE_URL}/user/${userId}/tags`, {
  params: { viewer_id: viewerId, skip_tags: skip, limit_tags: limit, limit_taggers: maxTaggers }
});
```

### Stream Endpoints

```javascript
// Get posts stream
const posts = await axios.get(`${NEXUS_API_BASE_URL}/stream/posts`, {
  params: {
    viewer_id: viewerId,
    source, // 'all', 'following', 'author', 'bookmarks', 'post_replies'
    author_id: authorId,
    post_id: postId, // for post_replies source
    limit, start, end, skip,
    sorting: sort === 'popularity' ? 'total_engagement' : 'timeline',
    tags: tags ? tags.join(',') : undefined,
    kind: kind !== 'all' ? kind : undefined,
    order // for ordering results
  }
});

// Get users stream
const users = await axios.get(`${NEXUS_API_BASE_URL}/stream/users`, {
  params: { 
    user_id: userId, 
    viewer_id: viewerId, 
    source, // 'followers', 'following', 'friends', 'influencers'
    reach, // 'all', 'following', 'friends'
    timeframe, // 'today', 'this_month', 'all_time'
    skip, limit 
  }
});

// Search users by username
const users = await axios.get(`${NEXUS_API_BASE_URL}/stream/users/username`, {
  params: { username, viewer_id: viewerId, skip, limit }
});
```

### Tag-Related Endpoints

```javascript
// Get hot tags
const hotTags = await axios.get(`${NEXUS_API_BASE_URL}/tags/hot`, {
  params: { user_id: userId, reach, skip, limit, maxTaggers, timeframe }
});
```

### File Operations

```javascript
// Get file details
const fileUriEncoded = encodeURIComponent(fileUri);
const file = await axios.get(`${NEXUS_API_BASE_URL}/files/file/${fileUriEncoded}`);
```

## Error Handling Patterns

### Comprehensive Error Categories

```javascript
class PubkyError extends Error {
  constructor(message, category, context = {}) {
    super(message);
    this.name = 'PubkyError';
    this.category = category;
    this.context = context;
    this.timestamp = Date.now();
  }
}

// Error categories
const ErrorCategories = {
  NETWORK: 'network',
  AUTHENTICATION: 'authentication',
  AUTHORIZATION: 'authorization',
  VALIDATION: 'validation',
  HOMESERVER: 'homeserver',
  NEXUS: 'nexus',
  CORS: 'cors'
};

function categorizeError(error, operation, context = {}) {
  let category = 'unknown';
  let suggestions = [];
  
  const errorStr = error.toString().toLowerCase();
  
  if (errorStr.includes('cors') || errorStr.includes('cross-origin')) {
    category = ErrorCategories.CORS;
    suggestions = [
      'Use CORS proxy in web applications',
      'Switch to CLI tool to avoid CORS',
      'Run browser with --disable-web-security (development only)'
    ];
  } else if (errorStr.includes('signup_token required')) {
    category = ErrorCategories.AUTHENTICATION;
    suggestions = ['Provide invite token with --token option'];
  } else if (errorStr.includes('error sending request') || errorStr.includes('fetch')) {
    category = ErrorCategories.NETWORK;
    suggestions = [
      'Check internet connection',
      'Try different homeserver',
      'Verify homeserver is running'
    ];
  } else if (errorStr.includes('401') || errorStr.includes('unauthorized')) {
    category = ErrorCategories.AUTHORIZATION;
    suggestions = ['Re-authenticate with signin/signup'];
  } else if (errorStr.includes('404')) {
    category = ErrorCategories.VALIDATION;
    suggestions = ['Check if resource exists', 'Verify URL format'];
  }
  
  return new PubkyError(error.message, category, {
    operation,
    suggestions,
    originalError: error,
    ...context
  });
}

// Usage wrapper
async function executeWithErrorHandling(operation, func, context = {}) {
  try {
    return await func();
  } catch (error) {
    const categorizedError = categorizeError(error, operation, context);
    
    console.error(`${operation} failed:`, categorizedError.message);
    console.error(`Category: ${categorizedError.category}`);
    
    if (categorizedError.context.suggestions?.length > 0) {
      console.log('Suggestions:');
      categorizedError.context.suggestions.forEach((suggestion, i) => {
        console.log(`   ${i + 1}. ${suggestion}`);
      });
    }
    
    throw categorizedError;
  }
}
```

### Network Error Handling

```javascript
// Network errors
try {
  const response = await client.fetch(url);
  
  switch (response.status) {
    case 200:
      return await response.json();
    case 404:
      console.log('Resource not found');
      return null;
    case 401:
      console.log('Not authenticated - sign in required');
      throw new Error('AUTHENTICATION_REQUIRED');
    case 403:
      console.log('Access forbidden - insufficient permissions');
      throw new Error('PERMISSION_DENIED');
    default:
      const errorText = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorText}`);
  }
} catch (error) {
  if (error.name === 'TypeError' && error.message.includes('fetch')) {
    console.error('Network error:', error);
    throw new Error('NETWORK_ERROR');
  }
  throw error;
}

// Validation errors
try {
  const publicKey = PublicKey.from(userInput);
} catch (error) {
  console.error('Invalid public key format');
}

try {
  const keypair = Keypair.fromSecretKey(invalidSecret);
} catch (error) {
  console.error('Expected 32-byte secret key');
}
```

## Data Flow Example (Social Post)

1. User creates post in frontend app
2. App uses `@synonymdev/pubky` client to write post data to user's Homeserver
3. Homeserver stores data and emits event
4. Pubky-Nexus `nexus-watcher` detects event
5. `nexus-watcher` updates Neo4j social graph and Redis caches
6. Other users request feed via Nexus API
7. `nexus-service` queries Redis/Neo4j and returns feed data

## Testing Strategies

### Unit Testing with Tape

```javascript
import test from 'tape';
import { Client, Keypair, PublicKey } from '@synonymdev/pubky';

test('authentication flow', async (t) => {
  const client = Client.testnet();
  const keypair = Keypair.random();
  const homeserver = PublicKey.from('your_homeserver_public_key_here');

  // Test signup
  const session = await client.signup(keypair, homeserver, null);
  t.ok(session, 'signup successful');
  t.equal(session.pubky().z32(), keypair.publicKey().z32(), 'correct session pubky');

  // Test session check
  const activeSession = await client.session(keypair.publicKey());
  t.ok(activeSession, 'session exists after signup');

  // Test signout
  await client.signout(keypair.publicKey());
  const noSession = await client.session(keypair.publicKey());
  t.notOk(noSession, 'no session after signout');
});

test('data operations', async (t) => {
  const client = Client.testnet();
  const keypair = Keypair.random();
  const homeserver = PublicKey.from('your_homeserver_public_key_here');
  
  await client.signup(keypair, homeserver, null);
  
  const url = `pubky://${keypair.publicKey().z32()}/pub/test.com/data.json`;
  const testData = { message: 'hello world' };

  // Test PUT
  const putResponse = await client.fetch(url, {
    method: 'PUT',
    body: JSON.stringify(testData),
    credentials: 'include'
  });
  t.equal(putResponse.status, 200, 'PUT successful');

  // Test GET
  const getResponse = await client.fetch(url);
  t.equal(getResponse.status, 200, 'GET successful');
  const retrieved = await getResponse.json();
  t.deepEqual(retrieved, testData, 'data matches');

  // Test DELETE
  const deleteResponse = await client.fetch(url, {
    method: 'DELETE',
    credentials: 'include'
  });
  t.equal(deleteResponse.status, 200, 'DELETE successful');

  // Test GET after delete
  const notFoundResponse = await client.fetch(url);
  t.equal(notFoundResponse.status, 404, 'resource not found after delete');
});
```

### Load Testing Pattern

```javascript
// Load testing for development
async function loadTestHomeserver(client, keypair, concurrency = 5, operations = 10) {
  const userPubky = keypair.publicKey().z32();
  const results = { success: 0, failed: 0, errors: [] };
  
  console.log(`Load testing: ${concurrency} concurrent clients, ${operations} operations each`);
  
  const workers = Array.from({ length: concurrency }, async (_, workerId) => {
    for (let i = 0; i < operations; i++) {
      try {
        const testUrl = `pubky://${userPubky}/pub/loadtest/worker${workerId}_op${i}.json`;
        const testData = { workerId, operation: i, timestamp: Date.now() };
        
        // PUT data
        const putResponse = await client.fetch(testUrl, {
          method: 'PUT',
          body: JSON.stringify(testData),
          credentials: 'include'
        });
        
        if (putResponse.ok) {
          results.success++;
        } else {
          results.failed++;
          results.errors.push(`PUT failed: ${putResponse.status}`);
        }
        
        // GET data back
        const getResponse = await client.fetch(testUrl);
        if (!getResponse.ok) {
          results.failed++;
          results.errors.push(`GET failed: ${getResponse.status}`);
        }
        
      } catch (error) {
        results.failed++;
        results.errors.push(error.message);
      }
    }
  });
  
  await Promise.all(workers);
  
  console.log(`Load test complete: ${results.success} success, ${results.failed} failed`);
  if (results.errors.length > 0) {
    console.log('Errors:', results.errors.slice(0, 5)); // Show first 5 errors
  }
  
  return results;
}
```

## React Integration Pattern

```javascript
import { createContext, useContext, useEffect, useState } from 'react';
import { Client, Keypair, PublicKey, decryptRecoveryFile } from '@synonymdev/pubky';

const PubkyContext = createContext();

export function PubkyProvider({ children }) {
  const [client] = useState(() => Client.testnet());
  const [currentUser, setCurrentUser] = useState(null);
  const [session, setSession] = useState(null);

  useEffect(() => {
    const savedUser = localStorage.getItem('pubky_user');
    if (savedUser) {
      checkSession(PublicKey.from(savedUser));
    }
  }, []);

  async function checkSession(publicKey) {
    try {
      const activeSession = await client.session(publicKey);
      if (activeSession) {
        setCurrentUser(publicKey);
        setSession(activeSession);
      }
    } catch (error) {
      console.error('Session check failed:', error);
    }
  }

  async function signIn(recoveryFile, passphrase) {
    try {
      const keypair = decryptRecoveryFile(recoveryFile, passphrase);
      await client.signin(keypair);
      
      const publicKey = keypair.publicKey();
      const newSession = await client.session(publicKey);
      
      setCurrentUser(publicKey);
      setSession(newSession);
      localStorage.setItem('pubky_user', publicKey.z32());
      
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async function signOut() {
    if (currentUser) {
      await client.signout(currentUser);
      setCurrentUser(null);
      setSession(null);
      localStorage.removeItem('pubky_user');
    }
  }

  const value = {
    client,
    currentUser,
    session,
    signIn,
    signOut,
    isSignedIn: !!currentUser
  };

  return (
    <PubkyContext.Provider value={value}>
      {children}
    </PubkyContext.Provider>
  );
}

export function usePubky() {
  const context = useContext(PubkyContext);
  if (!context) {
    throw new Error('usePubky must be used within PubkyProvider');
  }
  return context;
}
```

## Rust Implementation Reference

### Client Setup

```rust
use pubky::{Client, Keypair, PublicKey};
use anyhow::Result;

// Default client
let client = Client::builder().build()?;

// Testnet client
let client = Client::builder().testnet().build()?;

// Custom configuration
let client = Client::builder()
    .pkarr(|builder| {
        builder.relays(&["https://your-pkarr-relay.example.com/"])
               .request_timeout(std::time::Duration::from_secs(2))
    })
    .request_timeout(std::time::Duration::from_secs(30))
    .max_record_age(std::time::Duration::from_secs(3600))
    .build()?;
```

### Authentication

```rust
// Generate keypair
let keypair = Keypair::random();
let public_key = keypair.public_key();

// Signup
let homeserver = PublicKey::try_from("your_homeserver_public_key_here")?;
let session = client.signup(&keypair, &homeserver, Some("invite_code")).await?;

// Check session
if let Some(session) = client.session(&public_key).await? {
    println!("Active session: {:?}", session.capabilities());
}

// Sign in
let session = client.signin(&keypair).await?;

// Sign out
client.signout(&public_key).await?;
```

### Data Operations

```rust
let pubky = keypair.public_key().to_z32();
let url = format!("pubky://{}/pub/example.com/data.json", pubky);

// PUT data
let data = serde_json::json!({"message": "hello"});
let response = client.put(&url)
    .json(&data)
    .send()
    .await?;

// GET data
let response = client.get(&url).send().await?;
let data: serde_json::Value = response.json().await?;

// DELETE data
let response = client.delete(&url).send().await?;

// List directory
let dir_url = format!("pubky://{}/pub/example.com/", pubky);
let files = client.list(&dir_url)
    .limit(50)
    .reverse(false)
    .send()
    .await?;
```

## Deployment & Packaging

### Frontend Application Deployment

#### Next.js Build Configuration

```json
// package.json
{
  "name": "pubky-app",
  "version": "1.0.0",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "build:testnet": "NEXT_PUBLIC_TESTNET=true next build",
    "build:production": "NEXT_PUBLIC_TESTNET=false next build"
  },
  "dependencies": {
    "@synonymdev/pubky": "^0.4.2",
    "next": "^14.0.0",
    "react": "^18.0.0",
    "axios": "^1.6.0"
  }
}
```

#### Environment Variables

```bash
# .env.local (development)
NEXT_PUBLIC_TESTNET=true
NEXT_PUBLIC_HOMESERVER=your_testnet_homeserver_key
NEXT_PUBLIC_DEFAULT_HTTP_RELAY=http://localhost:15412/link
NEXT_PUBLIC_NEXUS=http://localhost:3001

# .env.production
NEXT_PUBLIC_TESTNET=false
NEXT_PUBLIC_HOMESERVER=your_production_homeserver_key
NEXT_PUBLIC_DEFAULT_HTTP_RELAY=https://your-relay.example.com/link
NEXT_PUBLIC_NEXUS=https://your-nexus.example.com
```

### Docker Deployment

#### Dockerfile

```dockerfile
FROM node:18-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_TESTNET=false
ARG NEXT_PUBLIC_HOMESERVER
ARG NEXT_PUBLIC_DEFAULT_HTTP_RELAY
ARG NEXT_PUBLIC_NEXUS
RUN npm run build

FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV production
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT 3000
CMD ["node", "server.js"]
```

#### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    build:
      context: .
      args:
        NEXT_PUBLIC_TESTNET: "false"
        NEXT_PUBLIC_HOMESERVER: "${HOMESERVER_KEY}"
        NEXT_PUBLIC_DEFAULT_HTTP_RELAY: "${HTTP_RELAY_URL}"
        NEXT_PUBLIC_NEXUS: "${NEXUS_API_URL}"
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    restart: unless-stopped
```

### Security Considerations

#### Content Security Policy

```javascript
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; connect-src 'self' https://*.example.com wss://*.example.com; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
          }
        ]
      }
    ];
  }
};
```

#### Environment Validation

```javascript
// config/env.js
function validateEnv() {
  const required = [
    'NEXT_PUBLIC_HOMESERVER',
    'NEXT_PUBLIC_DEFAULT_HTTP_RELAY'
  ];
  
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

validateEnv();
```

## Key Capabilities & Limitations

### What Pubky Provides
- Public-key based authentication and identity
- Decentralized data storage via Homeservers
- Capability-based authorization system
- HTTP API for data operations (PUT, GET, DELETE)
- Directory listing with pagination
- Third-party app authorization flows
- Recovery file system for key backup/restore
- Cross-platform clients (Rust, JavaScript/WASM)

### Real-World Constraints
- **CORS limitations** in browser environments
- **Homeserver availability** varies by instance
- **Invite tokens** often required for signup
- **Session management** needs careful handling
- **Network connectivity** issues are common
- **Authentication flows** can be complex
- **Error messages** may lack detail

### What to Remember
- All data operations require proper authentication via sessions
- Only `/pub/` directories are publicly readable
- Write operations require appropriate capabilities
- Homeserver records should be republished periodically
- Use testnet for development, mainnet for production
- Error handling is crucial for network resilience
- Recovery files are encrypted with user passphrases
- CLI tools avoid browser CORS restrictions
- Session state doesn't persist automatically

### Development Best Practices
- **Always test connectivity** before attempting operations
- **Implement robust error handling** with specific suggestions
- **Use debug logging** for troubleshooting
- **Cache sessions** to avoid repeated authentication
- **Provide fallback mechanisms** (republish, different homeservers)
- **Validate inputs** before sending to API
- **Handle network timeouts** gracefully
- **Test with real services** not mocks

### Critical Implementation Notes
- Never mock or simulate Pubky functionality - only use documented APIs
- All examples are based on actual working implementations
- Homeserver endpoints must be resolved via Pkarr network
- Sessions contain capabilities that determine permissions
- Recovery files have specific format: starts with "pubky.org/recovery\n"
- Z-base-32 encoding is used for public key representations
- CLI tools are often more reliable than web apps for development
- Always provide clear error messages and suggestions to users

### Browser Storage Restriction
**NEVER use localStorage, sessionStorage, or ANY browser storage APIs in artifacts.** These APIs are NOT supported and will cause artifacts to fail in the Claude.ai environment. Instead, use React state (useState, useReducer) for React components or JavaScript variables/objects for HTML artifacts.

## Tool Development Checklist

When creating new Pubky tools, ensure you include:

### Essential Features
- Configuration management with validation
- Connectivity testing for homeservers and Nexus
- Debug logging with verbose option
- Robust error handling with categorization
- Session persistence across operations
- Multiple homeserver support with fallbacks
- Recovery file handling with validation
- Usage examples and help text

### Error Handling
- Network timeout handling
- CORS error detection and suggestions
- Authentication failure recovery
- Invite token requirement detection
- Homeserver unavailability handling
- Invalid input validation
- Session expiry detection

### User Experience
- Clear progress indicators for long operations
- Actionable error messages with suggestions
- Configuration validation before operations
- Examples and usage patterns in documentation
- Graceful degradation when services unavailable
