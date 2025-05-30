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

**Pubky App Specs** - Data model validation and creation
- NPM package: `pubky-app-specs`
- Version: 0.3.4
- WASM-based validation and ID generation
- Provides structured JSON models for social media features

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
- `public_key`: z-base-32 encoded public key (52 characters)
- `pub/`: indicates public data
- `domain`: provides scoping (default: "pubky.app")
- `path`: specifies the resource

### Authentication Model
Uses AuthTokens - signed timestamps with capabilities that prove ownership of a public key and grant specific permissions.

### Core Principles

**Credible Exit** - Users can migrate data and identity between homeservers without losing content, connections, or identity. This prevents vendor lock-in and ensures user sovereignty.

**Censorship Resistance** - Achieved through flexible hosting and decentralized identity. Users can circumvent censorship by migrating to different homeservers while maintaining their public key identity.

**Semantic Social Graph** - Relationships between users and content are tagged with meaningful metadata, enabling weighted connections and sophisticated content curation based on relevance and trust levels.

## Pubky App Specs - Data Model Validation

### Installation & Setup

```bash
# Install the data model specs package
npm install pubky-app-specs

# Note: This package uses WASM, ensure your bundler supports WASM modules
```

### Core Usage Pattern

```javascript
import init, { PubkySpecsBuilder } from "pubky-app-specs";

async function initializePubkySpecs(pubkyId) {
  // 1. Initialize WASM module
  await init();
  
  // 2. Create specs builder with user's public key
  const specs = new PubkySpecsBuilder(pubkyId);
  
  return specs;
}
```

### Data Models and Validation

All data models are automatically sanitized and validated. Each model has:
- **Auto-generated IDs** (timestamp-based or hash-based)
- **Auto-generated paths** following Pubky conventions
- **Built-in validation** ensuring data integrity
- **Sanitization** removing invalid or dangerous content

### Core Data Types

#### PubkyAppUser (Profile)
```javascript
// Create user profile
const userResult = specs.createUser(
  "Alice",                                    // name (required, 3-50 chars)
  "Toxic maximalist.",                        // bio (optional, max 160 chars)
  "pubky://user_id/pub/pubky.app/files/img",  // image URL (optional, max 300 chars)
  [                                           // links (optional, max 5 links)
    { title: "GitHub", url: "https://github.com/alice" },
    { title: "Website", url: "https://alice.dev" }
  ],
  "Exploring decentralized tech."             // status (optional, max 50 chars)
);

// Access the validated user object and metadata
const user = userResult.user;
const meta = userResult.meta;

console.log("User name:", user.name);
console.log("Path:", meta.path);     // "/pub/pubky.app/profile.json"
console.log("URL:", meta.url);       // "pubky://user_id/pub/pubky.app/profile.json"
```

#### PubkyAppPost
```javascript
import { PubkyAppPostKind } from "pubky-app-specs";

// Create a simple text post
const postResult = specs.createPost(
  "Hello world! This is my first post.",      // content
  PubkyAppPostKind.Short,                     // kind: Short, Long, Image, Video, Link, File
  null,                                       // parent (for replies)
  null,                                       // embed (for reposts)
  ["pubky://user_id/pub/pubky.app/files/1"]   // attachments (optional)
);

const post = postResult.post;
const meta = postResult.meta;

console.log("Post ID:", meta.id);           // Auto-generated timestamp ID
console.log("Path:", meta.path);            // "/pub/pubky.app/posts/00321FCW75ZFY"
console.log("Content:", post.content);

// Edit an existing post (preserves original ID)
const editedResult = specs.editPost(
  post,                                       // original post object
  meta.id,                                    // original post ID
  "Updated content for my first post!"       // new content
);
```

#### PubkyAppTag
```javascript
// Tag a post or user
const tagResult = specs.createTag(
  "pubky://user_id/pub/pubky.app/posts/123",  // URI to tag
  "bitcoin"                                   // label (auto-sanitized: lowercase, no spaces)
);

const tag = tagResult.tag;
const meta = tagResult.meta;

console.log("Tag ID:", meta.id);            // Hash-based ID: "FPB0AM9S93Q3M1GFY1KV09GMQM"
console.log("Label:", tag.label);           // "bitcoin" (sanitized)
```

#### PubkyAppBookmark
```javascript
// Bookmark a post
const bookmarkResult = specs.createBookmark(
  "pubky://user_id/pub/pubky.app/posts/123"  // URI to bookmark
);

const bookmark = bookmarkResult.bookmark;
const meta = bookmarkResult.meta;

console.log("Bookmark ID:", meta.id);       // Hash-based ID from URI
```

#### PubkyAppFollow
```javascript
// Follow another user
const followResult = specs.createFollow(
  "operrr8wsbpr3ue9d4qj41ge1kcc6r7fdiy6o3ugjrrhi4y77rdo"  // user ID to follow
);

const follow = followResult.follow;
const meta = followResult.meta;

console.log("Follow path:", meta.path);     // "/pub/pubky.app/follows/user_id"
console.log("Created at:", follow.created_at);
```

#### PubkyAppMute
```javascript
// Mute a user
const muteResult = specs.createMute(
  "user_id_to_mute"                          // user ID to mute
);
```

#### PubkyAppFile
```javascript
// Create file metadata
const fileResult = specs.createFile(
  "example.png",                             // name
  "pubky://user_id/pub/pubky.app/blobs/123", // src (blob URL)
  "image/png",                               // content_type (IANA MIME type)
  1024                                       // size in bytes
);

const file = fileResult.file;
const meta = fileResult.meta;

console.log("File ID:", meta.id);           // Timestamp-based ID
```

#### PubkyAppBlob
```javascript
// Create blob from binary data
const blobData = new Uint8Array([1, 2, 3, 4]); // Your binary data
const blobResult = specs.createBlob(blobData);

const blob = blobResult.blob;
const meta = blobResult.meta;

console.log("Blob ID:", meta.id);           // Hash-based ID from content
```

#### PubkyAppFeed (Custom Perspectives)
```javascript
import { PubkyAppFeedReach, PubkyAppFeedLayout, PubkyAppFeedSort } from "pubky-app-specs";

const feedResult = specs.createFeed(
  ["bitcoin", "rust"],                       // tags filter
  PubkyAppFeedReach.Following,               // reach: Following, Followers, Friends, All
  PubkyAppFeedLayout.Columns,                // layout: Columns, Wide, Visual  
  PubkyAppFeedSort.Recent,                   // sort: Recent, Popularity
  PubkyAppPostKind.Image,                    // content filter (optional)
  "Bitcoin Developers"                       // feed name
);
```

#### PubkyAppLastRead
```javascript
// Track last read timestamp for notifications
const lastReadResult = specs.createLastRead();

const lastRead = lastReadResult.last_read;
console.log("Timestamp:", lastRead.timestamp);
```

### URI Parsing

```javascript
import { parse_uri } from "pubky-app-specs";

// Parse any Pubky URI
const uri = "pubky://user_id/pub/pubky.app/posts/00321FCW75ZFY";
const parsed = parse_uri(uri);

console.log("User ID:", parsed.user_id);     // "user_id"
console.log("Resource:", parsed.resource);   // "posts"
console.log("Resource ID:", parsed.resource_id); // "00321FCW75ZFY"
```

### JSON Serialization

All objects provide `toJson()` and `fromJson()` methods for WASM interop:

```javascript
// Convert to JSON for storage
const userJson = user.toJson();
const jsonString = JSON.stringify(userJson);

// Restore from JSON
const parsedJson = JSON.parse(jsonString);
const restoredUser = PubkyAppUser.fromJson(parsedJson);
```

## Integration with Pubky Client

### Complete Social Media Post Creation

```javascript
import { Client, Keypair } from "@synonymdev/pubky";
import init, { PubkySpecsBuilder, PubkyAppPostKind } from "pubky-app-specs";

async function createAndStorePost(keypair, content) {
  // Initialize
  const client = Client.testnet();
  await init();
  
  const pubkyId = keypair.publicKey().z32();
  const specs = new PubkySpecsBuilder(pubkyId);
  
  // Ensure authenticated
  await client.signin(keypair);
  
  // Create validated post
  const postResult = specs.createPost(
    content,
    PubkyAppPostKind.Short,
    null, null, null
  );
  
  // Store on homeserver
  const response = await client.fetch(postResult.meta.url, {
    method: 'PUT',
    body: JSON.stringify(postResult.post.toJson()),
    credentials: 'include'
  });
  
  if (!response.ok) {
    throw new Error(`Failed to store post: ${response.statusText}`);
  }
  
  console.log("Post stored at:", postResult.meta.url);
  return postResult;
}
```

### Profile Management

```javascript
async function updateProfile(client, specs, profileData) {
  const userResult = specs.createUser(
    profileData.name,
    profileData.bio,
    profileData.image,
    profileData.links,
    profileData.status
  );
  
  // Store profile
  await client.fetch(userResult.meta.url, {
    method: 'PUT',
    body: JSON.stringify(userResult.user.toJson()),
    credentials: 'include'
  });
  
  return userResult;
}

async function getProfile(client, pubkyId) {
  const url = `pubky://${pubkyId}/pub/pubky.app/profile.json`;
  const response = await client.fetch(url);
  
  if (response.status === 404) {
    return null; // No profile found
  }
  
  if (!response.ok) {
    throw new Error(`Failed to fetch profile: ${response.status}`);
  }
  
  return await response.json();
}
```

### Social Interactions

```javascript
async function followUser(client, specs, targetUserId) {
  const followResult = specs.createFollow(targetUserId);
  
  await client.fetch(followResult.meta.url, {
    method: 'PUT',
    body: JSON.stringify(followResult.follow.toJson()),
    credentials: 'include'
  });
  
  console.log(`Following user: ${targetUserId}`);
  return followResult;
}

async function tagPost(client, specs, postUri, label) {
  const tagResult = specs.createTag(postUri, label);
  
  await client.fetch(tagResult.meta.url, {
    method: 'PUT', 
    body: JSON.stringify(tagResult.tag.toJson()),
    credentials: 'include'
  });
  
  console.log(`Tagged ${postUri} with "${label}"`);
  return tagResult;
}

async function bookmarkPost(client, specs, postUri) {
  const bookmarkResult = specs.createBookmark(postUri);
  
  await client.fetch(bookmarkResult.meta.url, {
    method: 'PUT',
    body: JSON.stringify(bookmarkResult.bookmark.toJson()),
    credentials: 'include'
  });
  
  return bookmarkResult;
}
```

## Validation Rules and Constraints

### User Validation
- **Name**: 3-50 characters, cannot be "[DELETED]"
- **Bio**: Max 160 characters
- **Image**: Valid URL, max 300 characters
- **Links**: Max 5 links, each with title (100 chars) and valid URL (300 chars)
- **Status**: Max 50 characters

### Post Validation
- **Content**: Max 1000 chars (Short), 50000 chars (Long), cannot be "[DELETED]"
- **Kind**: Must be valid PubkyAppPostKind enum value
- **Parent**: Must be valid URI if present
- **Attachments**: Each must be valid URI

### Tag Validation
- **Label**: 1-20 characters, auto-sanitized (lowercase, no whitespace)
- **URI**: Must be valid URI format

### File Validation
- **Name**: 1-255 characters
- **Size**: Max 100MB
- **Content Type**: Valid IANA MIME types only
- **Src**: Must be valid URL, max 1024 characters

## ID Generation Patterns

### Timestamp IDs
Used for sequential content (posts, files):
```javascript
// Format: 13-character Crockford Base32 from microsecond timestamp
// Example: "00321FCW75ZFY"
const post = specs.createPost("Hello", PubkyAppPostKind.Short);
console.log(post.meta.id); // Generated from current timestamp
```

### Hash IDs  
Used for content-based uniqueness (tags, bookmarks):
```javascript
// Format: First half of Blake3 hash, Crockford Base32 encoded
// Example: "FPB0AM9S93Q3M1GFY1KV09GMQM"
const tag = specs.createTag("pubky://user/post", "bitcoin");
console.log(tag.meta.id); // Generated from "pubky://user/post:bitcoin"
```

### Path Generation
All paths follow the pattern `/pub/pubky.app/{resource}[/{id}]`:

```javascript
// User profile (no ID)
"/pub/pubky.app/profile.json"

// Posts with timestamp ID
"/pub/pubky.app/posts/00321FCW75ZFY"

// Tags with hash ID
"/pub/pubky.app/tags/FPB0AM9S93Q3M1GFY1KV09GMQM"

// Follows with user ID
"/pub/pubky.app/follows/operrr8wsbpr3ue9d4qj41ge1kcc6r7fdiy6o3ugjrrhi4y77rdo"
```

## Error Handling

### Validation Errors
```javascript
try {
  const userResult = specs.createUser("Al"); // Too short
} catch (error) {
  console.error("Validation failed:", error.message);
  // "Validation Error: Invalid name length"
}
```

### WASM Initialization Errors
```javascript
try {
  await init();
  const specs = new PubkySpecsBuilder("invalid_pubky_id");
} catch (error) {
  console.error("Invalid public key:", error.message);
}
```

### Network Errors with Validation
```javascript
async function safeCreatePost(client, specs, content) {
  try {
    // Validation happens here
    const postResult = specs.createPost(content, PubkyAppPostKind.Short);
    
    // Network operation
    const response = await client.fetch(postResult.meta.url, {
      method: 'PUT',
      body: JSON.stringify(postResult.post.toJson()),
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }
    
    return postResult;
    
  } catch (error) {
    if (error.message.includes('Validation Error')) {
      console.error('Content validation failed:', error.message);
    } else if (error.message.includes('HTTP')) {
      console.error('Network error:', error.message);
    } else {
      console.error('Unexpected error:', error.message);
    }
    throw error;
  }
}
```

## Advanced Usage Patterns

### Bulk Data Operations
```javascript
async function createBulkPosts(client, specs, posts) {
  const results = [];
  
  for (const postContent of posts) {
    try {
      const postResult = specs.createPost(postContent, PubkyAppPostKind.Short);
      
      await client.fetch(postResult.meta.url, {
        method: 'PUT',
        body: JSON.stringify(postResult.post.toJson()),
        credentials: 'include'
      });
      
      results.push({ success: true, post: postResult });
    } catch (error) {
      results.push({ success: false, error: error.message, content: postContent });
    }
  }
  
  return results;
}
```

### Custom Feed Management
```javascript
import { PubkyAppFeedReach, PubkyAppFeedLayout, PubkyAppFeedSort } from "pubky-app-specs";

async function saveCustomFeed(client, specs, feedConfig) {
  const feedResult = specs.createFeed(
    feedConfig.tags,
    PubkyAppFeedReach[feedConfig.reach],
    PubkyAppFeedLayout[feedConfig.layout], 
    PubkyAppFeedSort[feedConfig.sort],
    feedConfig.contentType ? PubkyAppPostKind[feedConfig.contentType] : null,
    feedConfig.name
  );
  
  await client.fetch(feedResult.meta.url, {
    method: 'PUT',
    body: JSON.stringify(feedResult.feed.toJson()),
    credentials: 'include'
  });
  
  return feedResult;
}
```

### File Upload with Metadata
```javascript
async function uploadFileWithMetadata(client, specs, fileData, metadata) {
  // First, create and store the blob
  const blobResult = specs.createBlob(fileData);
  
  await client.fetch(blobResult.meta.url, {
    method: 'PUT',
    body: blobResult.blob.data, // Access raw Uint8Array
    credentials: 'include'
  });
  
  // Then create file metadata pointing to the blob
  const fileResult = specs.createFile(
    metadata.name,
    blobResult.meta.url,        // Point to blob URL
    metadata.contentType,
    fileData.length
  );
  
  await client.fetch(fileResult.meta.url, {
    method: 'PUT',
    body: JSON.stringify(fileResult.file.toJson()),
    credentials: 'include'
  });
  
  return { blob: blobResult, file: fileResult };
}
```

## React Integration

```javascript
import { useState, useEffect } from 'react';
import init, { PubkySpecsBuilder } from 'pubky-app-specs';

function usePubkySpecs(pubkyId) {
  const [specs, setSpecs] = useState(null);
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    async function initializeSpecs() {
      try {
        await init();
        const specsBuilder = new PubkySpecsBuilder(pubkyId);
        setSpecs(specsBuilder);
        setIsReady(true);
      } catch (err) {
        setError(err.message);
      }
    }
    
    if (pubkyId) {
      initializeSpecs();
    }
  }, [pubkyId]);
  
  return { specs, isReady, error };
}

// Usage in component
function PostCreator({ client, pubkyId }) {
  const { specs, isReady, error } = usePubkySpecs(pubkyId);
  const [content, setContent] = useState('');
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!specs || !isReady) return;
    
    try {
      const postResult = specs.createPost(content, PubkyAppPostKind.Short);
      
      await client.fetch(postResult.meta.url, {
        method: 'PUT',
        body: JSON.stringify(postResult.post.toJson()),
        credentials: 'include'
      });
      
      console.log('Post created:', postResult.meta.url);
      setContent('');
    } catch (err) {
      console.error('Failed to create post:', err.message);
    }
  };
  
  if (error) return <div>Error: {error}</div>;
  if (!isReady) return <div>Loading specs...</div>;
  
  return (
    <form onSubmit={handleSubmit}>
      <textarea 
        value={content}
        onChange={(e) => setContent(e.target.value)}
        placeholder="What's on your mind?"
        maxLength={1000}
      />
      <button type="submit" disabled={!content.trim()}>
        Post
      </button>
    </form>
  );
}
```

## Installation & Setup

### Development Environment Setup

```bash
# Install Pubky client
npm install @synonymdev/pubky

# Install data model specs
npm install pubky-app-specs

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

## Pubky-Nexus API Integration

### Base Configuration

```javascript
const NEXUS_API_BASE_URL = process.env.NEXT_PUBLIC_NEXUS ? 
  `${process.env.NEXT_PUBLIC_NEXUS}/v0` : 
  'https://your-nexus-api.example.com/v0';
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
```

### Stream Endpoints

```javascript
// Get posts stream
const posts = await axios.get(`${NEXUS_API_BASE_URL}/stream/posts`, {
  params: {
    viewer_id: viewerId,
    source, // 'all', 'following', 'author', 'bookmarks'
    author_id: authorId,
    limit, start, end, skip,
    sorting: sort === 'popularity' ? 'total_engagement' : 'timeline',
    tags: tags ? tags.join(',') : undefined,
    kind: kind !== 'all' ? kind : undefined
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

// Get post tags
const postTags = await axios.get(`${NEXUS_API_BASE_URL}/post/${userId}/${postId}/tags`, {
  params: { viewer_id: viewerId, skip_tags: skip, limit_tags: limit, limit_taggers: maxTaggers }
});

// Get user tags
const userTags = await axios.get(`${NEXUS_API_BASE_URL}/user/${userId}/tags`, {
  params: { viewer_id: viewerId, skip_tags: skip, limit_tags: limit, limit_taggers: maxTaggers }
});
```

### File Operations

```javascript
// Get file details
const fileUriEncoded = encodeURIComponent(fileUri);
const file = await axios.get(`${NEXUS_API_BASE_URL}/files/file/${fileUriEncoded}`);
```

## Error Handling Patterns

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
2. App uses `pubky-app-specs` to validate and create structured post data
3. App uses `@synonymdev/pubky` client to write post data to user's Homeserver
4. Homeserver stores data and emits event
5. Pubky-Nexus `nexus-watcher` detects event
6. `nexus-watcher` updates Neo4j social graph and Redis caches
7. Other users request feed via Nexus API
8. `nexus-service` queries Redis/Neo4j and returns feed data

## Testing Strategies

### Unit Testing with Tape

```javascript
import test from 'tape';
import { Client, Keypair, PublicKey } from '@synonymdev/pubky';
import init, { PubkySpecsBuilder, PubkyAppPostKind } from 'pubky-app-specs';

test('data model validation', async (t) => {
  await init();
  const pubkyId = 'operrr8wsbpr3ue9d4qj41ge1kcc6r7fdiy6o3ugjrrhi4y77rdo';
  const specs = new PubkySpecsBuilder(pubkyId);

  // Test user creation and validation
  const userResult = specs.createUser("Alice", "Bio", null, null, null);
  t.ok(userResult.user, 'user created successfully');
  t.equal(userResult.user.name, "Alice", 'user name correct');
  t.equal(userResult.meta.path, "/pub/pubky.app/profile.json", 'user path correct');

  // Test post creation with validation
  const postResult = specs.createPost("Hello world", PubkyAppPostKind.Short, null, null, null);
  t.ok(postResult.post, 'post created successfully');
  t.equal(postResult.post.content, "Hello world", 'post content correct');
  t.ok(postResult.meta.id.length === 13, 'post ID has correct length');
});

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

test('data operations with validation', async (t) => {
  await init();
  const client = Client.testnet();
  const keypair = Keypair.random();
  const homeserver = PublicKey.from('your_homeserver_public_key_here');
  
  await client.signup(keypair, homeserver, null);
  
  const pubkyId = keypair.publicKey().z32();
  const specs = new PubkySpecsBuilder(pubkyId);
  
  // Create and store validated post
  const postResult = specs.createPost("Test content", PubkyAppPostKind.Short, null, null, null);
  
  // Test PUT
  const putResponse = await client.fetch(postResult.meta.url, {
    method: 'PUT',
    body: JSON.stringify(postResult.post.toJson()),
    credentials: 'include'
  });
  t.equal(putResponse.status, 200, 'PUT successful');

  // Test GET
  const getResponse = await client.fetch(postResult.meta.url);
  t.equal(getResponse.status, 200, 'GET successful');
  const retrieved = await getResponse.json();
  t.equal(retrieved.content, "Test content", 'content matches');

  // Test DELETE
  const deleteResponse = await client.fetch(postResult.meta.url, {
    method: 'DELETE',
    credentials: 'include'
  });
  t.equal(deleteResponse.status, 200, 'DELETE successful');

  // Test GET after delete
  const notFoundResponse = await client.fetch(postResult.meta.url);
  t.equal(notFoundResponse.status, 404, 'resource not found after delete');
});
```

## React Integration Pattern

```javascript
import { createContext, useContext, useEffect, useState } from 'react';
import { Client, Keypair, PublicKey, decryptRecoveryFile } from '@synonymdev/pubky';
import init, { PubkySpecsBuilder } from 'pubky-app-specs';

const PubkyContext = createContext();

export function PubkyProvider({ children }) {
  const [client] = useState(() => Client.testnet());
  const [currentUser, setCurrentUser] = useState(null);
  const [session, setSession] = useState(null);
  const [specs, setSpecs] = useState(null);

  useEffect(() => {
    const savedUser = localStorage.getItem('pubky_user');
    if (savedUser) {
      checkSession(PublicKey.from(savedUser));
    }
  }, []);

  useEffect(() => {
    async function initializeSpecs() {
      if (currentUser) {
        await init();
        const specsBuilder = new PubkySpecsBuilder(currentUser.z32());
        setSpecs(specsBuilder);
      } else {
        setSpecs(null);
      }
    }
    
    initializeSpecs();
  }, [currentUser]);

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
      setSpecs(null);
      localStorage.removeItem('pubky_user');
    }
  }

  const value = {
    client,
    currentUser,
    session,
    specs,
    signIn,
    signOut,
    isSignedIn: !!currentUser,
    isReady: !!specs
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

## Environment Configuration

```javascript
class Environment {
  static getConfig() {
    const env = process.env.NODE_ENV || 'development';
    
    const configs = {
      development: {
        client: () => Client.testnet(),
        homeserver: 'your_testnet_homeserver_key_here',
        relays: ['http://localhost:15412/link']
      },
      
      production: {
        client: () => new Client({
          pkarr: {
            relays: ['https://your-pkarr-relay1.example.com/', 'https://your-pkarr-relay2.example.com/'],
            requestTimeout: 10000
          },
          userMaxRecordAge: 3600
        }),
        homeserver: 'your_production_homeserver_key_here',
        relays: ['https://your-http-relay.example.com/link']
      }
    };
    
    return configs[env] || configs.development;
  }
}
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
- Validated data models with auto-generated IDs and paths

### What pubky-app-specs Provides
- **Data validation** ensuring integrity and consistency
- **Automatic sanitization** removing invalid content
- **ID generation** (timestamp-based and hash-based)
- **Path generation** following Pubky conventions
- **Type safety** through WASM bindings
- **JSON serialization** for storage and transport
- **URI parsing** for resource identification

### What to Remember
- All data operations require proper authentication via sessions
- Only `/pub/` directories are publicly readable
- Write operations require appropriate capabilities
- Homeserver records should be republished periodically
- Use testnet for development, mainnet for production
- Error handling is crucial for network resilience
- Recovery files are encrypted with user passphrases
- Always initialize WASM module before using pubky-app-specs
- Data models are automatically validated and sanitized
- IDs and paths are generated following strict conventions

### Critical Implementation Notes
- Never mock or simulate Pubky functionality - only use documented APIs
- All examples are based on actual working implementations
- Homeserver endpoints must be resolved via Pkarr network
- Sessions contain capabilities that determine permissions
- Z-base-32 encoding is used for public key representations
- pubky-app-specs requires WASM initialization before use
- Validation errors provide specific messages about what's wrong
- All data models follow the `/pub/pubky.app/` path convention

## Development checklist
When creating new pubky projects make sure you follow the checklist:
### Essential Features
- Configuration management with validation
- Connectivity testing for homeservers and Nexus
- Debug logging with verbose option
- Robust error handling with categorization
- Session persistence across operations
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