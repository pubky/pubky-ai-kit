# Complete Pubky Protocol Development Guide for LLMs

> **CRITICAL**: This guide contains only actual functionality from the Pubky protocol. Do not mock, simulate, or invent any features not explicitly documented here. All code examples are based on real API implementations.

## Core Architecture & Concepts

### Pubky Protocol Overview
Pubky is an open protocol for per-public-key backends enabling censorship-resistant web applications. It combines public-key based DNS (Pkarr) with conventional web technologies for decentralized identity and data storage.

### Core Components

**Client** - Available in Rust and JavaScript/WebAssembly
- Handles authentication, data operations, protocol communication
- Rust crate: `pubky`
- NPM package: `@synonymdev/pubky`
- React Native package: `@synonymdev/react-native-pubky`
- Prefer one shared `Pubky` facade per app/process instead of creating a new client for every request.

**Pubky App Specs** - Data model validation and creation
- NPM package: `pubky-app-specs`
- Version: 0.5.x
- WASM-based validation and ID generation
- Provides structured JSON models for social media features
- Includes `collection` posts; use `createCollectionPost()` and only store canonical pubky.app post URIs in Collection items.

**Homeserver** - User's personal backend
- Provides storage and HTTP endpoints
- Validates authentication tokens and manages user data
- App-facing API is **file storage only**: HTTP `PUT` / `GET` / `DELETE` against `pubky://<pk>/pub/...` paths. Each entry is an opaque byte blob with a MIME type — typically JSON (e.g. `pubky-app-specs` post/profile records) but equally images, audio, video, PDFs, encrypted ciphertext, or any other format the app chooses. No protocol-level restriction on content type.
- Public `/pub` data is implemented today. Private app storage roots such as `/priv` are not formalized and must not be described as available.
- Can be operated by individuals, cooperatives, or commercial entities
- Internally the homeserver uses **PostgreSQL** for its own metadata - users (Ed25519 pubkey + quota), sessions (capability-scoped auth), entries (per-file path, blake3 hash, length, MIME, timestamps), events (PUT/DEL stream consumed by Nexus, Pubky Backup, and other subscribers), and signup codes. **Applications never connect to PostgreSQL directly** - they only see the file API.
- Default per-request payload limit: **10 MB** (returns `413` past that). This is independent of per-user quotas, which are operator-defined - for reference, Synonym's public homeserver enforces 1 GB per user with a 10 MB per file ceiling.
- Homeservers may enforce per-user rate limits. Treat `429` as a normal operational condition and retry with backoff.

**Pkarr Network** - Distributed DNS alternative
- Uses public keys as domains via Mainline DHT
- Resolves `pubky://` URLs to homeserver endpoints
- Leverages BitTorrent's Mainline DHT for data distribution
- Records are ephemeral and need periodic republishing

**Pubky-Nexus** - Backend aggregation service
- Aggregates, indexes, and caches data from multiple Homeservers
- Provides higher-level REST API for social applications (Nexus is in active development; API still on /v0 with breaking changes possible)
- Components: nexus-watcher, nexus-webapi, nexus-common, nexusd
- Databases: Neo4j (social graph), Redis (caching)

**Pubky Backup** - Local backup application
- Maintains a local copy of one or more users' public `/pub` data.
- Uses homeserver event streams and persisted cursors to keep local files up to date.
- Provides local snapshots and activity logs.
- Current release is one-way local backup only. Do not claim it restores data to homeservers, mirrors between homeservers, or provides cloud storage.

### URL Structure
```
// Preferred public-storage address used by SDK APIs
pubky<public_key>/pub/<path>

// URL/deeplink form also accepted by SDK parsers
pubky://<public_key>/pub/<path>

// Signed-in session storage path
/pub/<path>
```
- `public_key`: z-base-32 encoded public key, normally displayed with the `pubky` prefix.
- `/pub`: the only protocol-required top-level directory; everything after is app-chosen.

Use the signed-in session path (`/pub/app/file.json`) when reading or writing the current user's own storage through `session.storage`. Use the addressed form (`pubky<user>/pub/app/file.json` or `pubky://<user>/pub/app/file.json`) when reading someone else's public data through `pubky.publicStorage`.

Public key string formats matter:

- Display/human identifier: `publicKey.toString()` returns `pubky<z32>`. Use this in UI, logs, and human-facing references.
- Transport/storage identifier: `publicKey.z32()` returns raw z-base-32. Use this for hostnames, `_pubky.<z32>` DNS names, headers, query params, serde/JSON fields that expect a raw key, and database keys.

Only `/pub` is formalized today. The protocol leaves room for other top-level roots alongside it (`/priv` for private/encrypted data is the long-standing placeholder), but none have been formalized yet.

By convention the first segment under `/pub` is a **scope**, and an app may touch several. Real-world examples:

- **[Mapky](https://mapky.app)** writes its own data under `/pub/mapky.app/*` and uses `/pub/pubky.app/*` to reuse the user's profile and otherwise interop with pubky.app where it benefits either app.
- **Bitkit** writes app-specific state under `/pub/bitkit.to/*` and uses `/pub/paykit/*` for the Paykit protocol — a cross-app scope shared between Paykit-implementing apps.

Common scope flavors:

- **app-domain** (`pubky.app`, `mapky.app`, `bitkit.to`) — an app's own data
- **protocol** (`paykit`) — a shared standard

### Authentication Model
Uses AuthTokens - signed timestamps with capabilities that prove ownership of a public key and grant specific permissions. Tokens are valid for a 3-minute window to account for clock drift.

Third-party apps should use SDK auth flows instead of asking users to paste keys or mnemonics. `startAuthFlow()` creates a `pubkyauth://` authorization URL for a key manager such as Pubky Ring, and `resumeAuthFlow()` can recover the same flow after a page refresh or app switch. The authorization URL contains a `client_secret`; store it only in short-lived storage such as `sessionStorage`, and delete it once approved or abandoned.

An auth flow has state. Do not call `awaitApproval()` or `tryPollOnce()` concurrently on the same flow, and do not keep polling after completion; the SDK can return `ClientStateError`.

> **Known limitation**: All sessions currently share a single authentication cookie ([pubky-core#122](https://github.com/pubky/pubky-core/issues/122)) - signing into App B overwrites App A's session. A rework is in progress, building on a JWT-based solution.

### Core Principles

**Credible Exit** - Users can migrate identity by republishing homeserver records, and they can keep independent local copies of public data with Pubky Backup. Full homeserver-to-homeserver mirroring and automated restore are planned/future work, not current shipped behavior.

**Censorship Resistance** - Achieved through flexible hosting and decentralized identity. Users can circumvent censorship by migrating to different homeservers while maintaining their public key identity.

**Semantic Social Graph** - Relationships between users and content are tagged with meaningful metadata, enabling weighted connections and sophisticated content curation based on relevance and trust levels.

## Pubky App Specs - Data Model Validation

### Installation & Setup

```bash
# Install the data model specs package
npm install pubky-app-specs
```

### Core Usage Pattern

```javascript
import { PubkySpecsBuilder } from "pubky-app-specs";

function initializePubkySpecs(pubkyId) {
  // Create specs builder with user's public key.
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
  PubkyAppPostKind.Short,                     // kind: Short, Long, Image, Video, Link, File, Collection
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

// Create a Collection post with a typed JSON envelope in `content`.
// Items must be exact pubky.app post URIs with a valid 52-char pubky id
// and a valid 13-char Crockford post id.
const collectionResult = specs.createCollectionPost(
  "AI papers",
  "Best stuff",
  [
    "pubky://operrr8wsbpr3ue9d4qj41ge1kcc6r7fdiy6o3ugjrrhi4y77rdo/pub/pubky.app/posts/00321FCW75ZFY"
  ]
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
const feedResult = specs.createFeed(
  ["bitcoin", "rust"],                       // tags filter
  "following",                               // reach: "following" | "followers" | "friends" | "all"
  "columns",                                 // layout: "columns" | "wide" | "visual"
  "recent",                                  // sort: "recent" | "popularity"
  "image",                                   // content filter (optional): "short" | "long" | "image" | "video" | "link" | "file" | "collection"
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
import { Pubky, Keypair } from "@synonymdev/pubky";
import { PubkySpecsBuilder, PubkyAppPostKind } from "pubky-app-specs";

async function createAndStorePost(keypair, content) {
  // Initialize
  const pubky = Pubky.testnet();

  const pubkyId = keypair.publicKey.z32();
  const specs = new PubkySpecsBuilder(pubkyId);

  // Ensure authenticated
  const session = await pubky.signer(keypair).signin();

  // Create validated post
  const postResult = specs.createPost(
    content,
    PubkyAppPostKind.Short,
    null, null, null
  );

  // Store on homeserver
  await session.storage.putJson(postResult.meta.path, postResult.post.toJson());

  console.log("Post stored at:", postResult.meta.url);
  return postResult;
}
```

### Profile Management

```javascript
async function updateProfile(session, specs, profileData) {
  const userResult = specs.createUser(
    profileData.name,
    profileData.bio,
    profileData.image,
    profileData.links,
    profileData.status
  );

  // Store profile (own data → session.storage)
  await session.storage.putJson(userResult.meta.path, userResult.user.toJson());

  return userResult;
}

async function getProfile(pubky, publicKey) {
  // Reading another user's public data -> pubky.publicStorage.
  // `publicKey` may be a PublicKey object or a display string like pubky<z32>.
  const user = typeof publicKey === 'string' ? publicKey : publicKey.toString();
  const address = `${user}/pub/pubky.app/profile.json`;
  try {
    return await pubky.publicStorage.getJson(address);
  } catch (e) {
    const error = e; // PubkyError
    if (error.name === 'RequestError' && error.data?.statusCode === 404) return null;
    throw e;
  }
}
```

### Social Interactions

```javascript
async function followUser(session, specs, targetUserId) {
  const followResult = specs.createFollow(targetUserId);

  await session.storage.putJson(followResult.meta.path, followResult.follow.toJson());

  console.log(`Following user: ${targetUserId}`);
  return followResult;
}

async function tagPost(session, specs, postUri, label) {
  const tagResult = specs.createTag(postUri, label);

  await session.storage.putJson(tagResult.meta.path, tagResult.tag.toJson());

  console.log(`Tagged ${postUri} with "${label}"`);
  return tagResult;
}

async function bookmarkPost(session, specs, postUri) {
  const bookmarkResult = specs.createBookmark(postUri);

  await session.storage.putJson(bookmarkResult.meta.path, bookmarkResult.bookmark.toJson());

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
- **Content**: Max 2000 chars (Short), 50000 chars (Long), cannot be "[DELETED]"
- **Kind**: Must be valid PubkyAppPostKind enum value: Short, Long, Image, Video, Link, File, or Collection. `Unknown` is for forward-compatible deserialization only and should not be generated.
- **Parent**: Must be valid URI if present
- **Attachments**: Max 4; each must be a valid `pubky`, `http`, or `https` URI, max 200 chars
- **Collection**: Use `createCollectionPost(name, description, items)`. `name` is 1-100 chars, `description` is optional up to 500 chars, `items` is max 100 exact post URIs of the form `pubky://<pubky-id>/pub/pubky.app/posts/<post-id>`, and parent/embed/attachments must be unset.

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

### Invalid Public Key Errors
```javascript
try {
  const specs = new PubkySpecsBuilder("invalid_pubky_id");
} catch (error) {
  console.error("Invalid public key:", error.message);
}
```

### Network Errors with Validation
```javascript
async function safeCreatePost(session, specs, content) {
  try {
    // Validation happens here
    const postResult = specs.createPost(content, PubkyAppPostKind.Short);

    // Network operation — throws PubkyError on failure
    await session.storage.putJson(postResult.meta.path, postResult.post.toJson());

    return postResult;

  } catch (error) {
    if (error.message.includes('Validation Error')) {
      console.error('Content validation failed:', error.message);
    } else if (error.name === 'RequestError') {
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
async function createBulkPosts(session, specs, posts) {
  const results = [];

  for (const postContent of posts) {
    try {
      const postResult = specs.createPost(postContent, PubkyAppPostKind.Short);

      await session.storage.putJson(postResult.meta.path, postResult.post.toJson());

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
async function saveCustomFeed(session, specs, feedConfig) {
  const feedResult = specs.createFeed(
    feedConfig.tags,
    feedConfig.reach,         // "following" | "followers" | "friends" | "all"
    feedConfig.layout,        // "columns" | "wide" | "visual"
    feedConfig.sort,          // "recent" | "popularity"
    feedConfig.contentType ?? null,  // (optional) "short" | "long" | "image" | "video" | "link" | "file" | "collection"
    feedConfig.name
  );

  await session.storage.putJson(feedResult.meta.path, feedResult.feed.toJson());

  return feedResult;
}
```

### File Upload with Metadata
```javascript
async function uploadFileWithMetadata(session, specs, fileData, metadata) {
  // First, create and store the blob
  const blobResult = specs.createBlob(fileData);

  await session.storage.putBytes(blobResult.meta.path, blobResult.blob.data);

  // Then create file metadata pointing to the blob
  const fileResult = specs.createFile(
    metadata.name,
    blobResult.meta.url,        // Point to blob URL
    metadata.contentType,
    fileData.length
  );

  await session.storage.putJson(fileResult.meta.path, fileResult.file.toJson());

  return { blob: blobResult, file: fileResult };
}
```

## React Integration

```javascript
import { useState, useEffect } from 'react';
import { PubkySpecsBuilder } from 'pubky-app-specs';

function usePubkySpecs(pubkyId) {
  const [specs, setSpecs] = useState(null);
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!pubkyId) return;
    try {
      setSpecs(new PubkySpecsBuilder(pubkyId));
      setIsReady(true);
    } catch (err) {
      setError(err.message);
    }
  }, [pubkyId]);

  return { specs, isReady, error };
}

// Usage in component
function PostCreator({ session, pubkyId }) {
  const { specs, isReady, error } = usePubkySpecs(pubkyId);
  const [content, setContent] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!specs || !isReady) return;

    try {
      const postResult = specs.createPost(content, PubkyAppPostKind.Short);

      await session.storage.putJson(postResult.meta.path, postResult.post.toJson());

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
        maxLength={2000}
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
import { Pubky, Keypair, PublicKey, Client } from "@synonymdev/pubky";

// Default client (mainnet)
const pubky = new Pubky();

// Testnet client for development
const pubkyTestnet = Pubky.testnet();

// Custom configuration
const client = new Client({
  pkarr: {
    relays: ['https://your-pkarr-relay.example.com/'],
    requestTimeout: 2000
  }
});
const pubkyCustom = Pubky.withClient(client);
```

### Authentication Flows

```javascript
// Signup to homeserver
const homeserver = PublicKey.from('your_homeserver_public_key_here');
const signupToken = 'optional_invite_code';

const signer = pubky.signer(keypair);

try {
  const session = await signer.signup(homeserver, signupToken);
  console.log('Signed up:', session.info.publicKey.toString());
  console.log('Capabilities:', session.info.capabilities);
} catch (error) {
  console.error('Signup failed:', error);
}

// Sign in existing user
const session = await signer.signin();

// Sign out
await session.signout();

// Get user's homeserver
try {
  const homeserverKey = await pubky.getHomeserverOf(publicKey);
  console.log('Homeserver:', homeserverKey.z32());
} catch (error) {
  console.log('No homeserver found');
}

// Republish homeserver record (for key managers)
await signer.pkdns.publishHomeserverIfStale(homeserverPublicKey);
```

### Data Operations

```javascript
// All session-scoped storage uses the user's own /pub paths.
const path = '/pub/example.com/todos.json';
const data = [
  { text: 'Buy milk', done: false },
  { text: 'Walk the dog', done: true },
];

// PUT JSON
await session.storage.putJson(path, data);

// GET JSON
const todos = await session.storage.getJson(path);
console.log('Todos:', todos);

// DELETE
await session.storage.delete(path);

// PUT binary data — e.g. an attachment for a todo
const photoBytes = new Uint8Array([/* image bytes */]);
await session.storage.putBytes('/pub/example.com/attachments/todo-1.png', photoBytes);
```

### Directory Listing

```javascript
// List directory contents (path must end with `/`)
const dirPath = '/pub/example.com/';

// Basic listing
const files = await session.storage.list(dirPath);

// With options: list(path, cursor, reverse, limit, shallow)
const firstTen = await session.storage.list(dirPath, null, false, 10, false);

// Paginated listing
let cursor = null;
const allFiles = [];
let batch;
do {
  batch = await session.storage.list(dirPath, cursor, false, 50);
  allFiles.push(...batch);
  cursor = batch.length > 0 ? batch[batch.length - 1] : null;
} while (cursor && batch.length === 50);

// Shallow listing (directories and files, not flat)
const directories = await session.storage.list(dirPath, null, false, null, true);
```

### Third-Party Authorization

```javascript
import { AuthFlowKind, validateCapabilities } from "@synonymdev/pubky";

// App requests authorization.
// Synonym-hosted HTTP relay; pass your own URL to use a different one.
const relay = "https://httprelay.pubky.app/inbox";
const capabilities = "/pub/myapp.com/:rw,/pub/shared/:r";

// Validate user-constructed capability strings before starting a flow.
validateCapabilities(capabilities);

const flow = pubky.startAuthFlow(capabilities, AuthFlowKind.signin(), relay);
const authUrl = flow.authorizationUrl; // property, not method

// The URL contains client_secret. The relay inbox is short-lived; treat it
// as a roughly five-minute recovery window, not durable app state.
// If a browser app must survive refresh, save it in sessionStorage only and
// remove it after completion/abandonment.
sessionStorage.setItem('pubky_auth_url', authUrl);

// Show QR code, deeplink, or redirect user to authUrl.
console.log('Visit:', authUrl);

try {
  const resumed = pubky.resumeAuthFlow(
    sessionStorage.getItem('pubky_auth_url') ?? authUrl
  );
  const session = await resumed.awaitApproval();
  sessionStorage.removeItem('pubky_auth_url');
  console.log('Authorized by:', session.info.publicKey.toString());
  console.log('Granted capabilities:', session.info.capabilities);
} catch (error) {
  sessionStorage.removeItem('pubky_auth_url');
  console.error('Authorization failed:', error);
}

// User authorizes the request in a key manager, e.g. Pubky Ring.
await signer.approveAuthRequest(authUrl);
```

## Event Streams

Use event streams for indexing, backup, sync, and watchers. Do not poll or recursively list whole `/pub` trees when an event stream is available.

```javascript
// Follow one user's homeserver events from the last persisted cursor.
const stream = await pubky
  .eventStreamForUser(userPublicKey, lastCursor ?? undefined)
  .path('/pub/pubky.app/')
  .limit(50)
  .subscribe();

const reader = stream.getReader();
while (true) {
  const { value: event, done } = await reader.read();
  if (done) break;

  // event.eventType is 'PUT' or 'DEL'.
  // event.cursor is the resumable checkpoint. Persist it after processing.
  // event.contentHash is present for PUT events.
  if (event.eventType === 'PUT') {
    const data = await pubky.publicStorage.getBytes(event.resource.toPubkyId());
    await updateIndex(event.resource.path, data, event.contentHash);
  } else {
    await removeFromIndex(event.resource.path);
  }

  await saveCursor(event.cursor);
}
```

For multiple users on a known homeserver, prefer `eventStreamFor(homeserver).addUsers(...)` so the SDK does not repeat PKARR lookups. Keep batches modest, persist cursors often, and back off on `429` because homeservers may enforce per-user limits.

`live()` streams historical events and then stays open for new events. `reverse()` gives newest-first historical results and closes; do not combine `live()` and `reverse()` on the same builder.

## Pubky-Nexus API Integration

> The Nexus REST API is on `/v0` and is **explicitly unstable** — breaking
> changes can land at any time. Treat the endpoint shapes below as
> illustrative; the Swagger UIs are the source of truth:
> https://nexus.pubky.app/swagger-ui/ (production) and
> https://nexus.staging.pubky.app/swagger-ui/ (staging).

### Base Configuration

```javascript
// Synonym-hosted Nexus; set NEXT_PUBLIC_NEXUS to use a different instance.
const NEXUS_API_BASE_URL = process.env.NEXT_PUBLIC_NEXUS ?
  `${process.env.NEXT_PUBLIC_NEXUS}/v0` :
  'https://nexus.pubky.app/v0';
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

SDK errors expose a stable `name` and, for many request failures, structured `data.statusCode`. Prefer structured checks over string matching. Known JS SDK names are `RequestError`, `InvalidInput`, `AuthenticationError`, `PkarrError`, `ClientStateError`, and `InternalError`.

```javascript
try {
  return await session.storage.getJson(path);
} catch (e) {
  const error = e; // PubkyError
  switch (error.name) {
    case 'RequestError':
      if (error.data?.statusCode === 404) return null;
      if (error.data?.statusCode === 429) {
        await backoffAndRetry();
        return;
      }
      console.error('Request failed:', error.message);
      throw error;
    case 'AuthenticationError':
      throw new Error('AUTHENTICATION_REQUIRED');
    case 'PkarrError':
      console.error('PKARR resolution failed:', error.message);
      throw error;
    case 'ClientStateError':
      console.error('SDK object was used in an invalid state:', error.message);
      throw error;
    case 'InvalidInput':
      console.error('Invalid SDK input:', error.message);
      throw error;
    default:
      throw error;
  }
}

try {
  const publicKey = PublicKey.from(userInput);
} catch (error) {
  console.error('Invalid public key format');
}
```

## Data Flow Example (Social Post)

1. User creates post in frontend app
2. App uses `pubky-app-specs` to validate and create structured post data
3. App uses `@synonymdev/pubky` client to write post data to user's Homeserver
4. Homeserver stores data and emits a `PUT` event with a cursor and content hash
5. Pubky-Nexus, Pubky Backup, or another subscriber consumes the event stream
6. Nexus updates Neo4j social graph and Redis caches
7. Pubky Backup fetches the changed public resource and stores a local copy
8. Other users request feed via Nexus API or read public resources directly

## Pubky Backup

Pubky Backup is the released local credible-exit tool for public data. It is a desktop app with a Rust core and Tauri frontend. Its core model is useful when generating backup/indexer code:

- Add one or more pubkeys, validate homeserver discovery, and start a controller per key.
- Subscribe to homeserver event streams with a persisted cursor.
- Process `PUT` by fetching the public resource and writing it locally.
- Process `DEL` by deleting the local file.
- Persist the cursor frequently so sync is resumable.
- Support force sync, remove-key-with-data-preserved, delete-key-with-data-removed, activity logs, and snapshots.

Current behavior is intentionally one-way. Do not tell users Pubky Backup can restore to a homeserver, mirror one homeserver to another, perform cloud backup, or do two-way sync. Those are roadmap/open-work areas.

## Testing Strategies

### Unit Testing with Tape

```javascript
import test from 'tape';
import { Pubky, Keypair, PublicKey } from '@synonymdev/pubky';
import { PubkySpecsBuilder, PubkyAppPostKind } from 'pubky-app-specs';

test('data model validation', (t) => {
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
  t.end();
});

test('authentication flow', async (t) => {
  const pubky = Pubky.testnet();
  const keypair = Keypair.random();
  const homeserver = PublicKey.from('your_homeserver_public_key_here');

  const signer = pubky.signer(keypair);

  // Test signup
  const session = await signer.signup(homeserver, null);
  t.ok(session, 'signup successful');
  t.equal(session.info.publicKey.z32(), keypair.publicKey.z32(), 'correct session pubky');

  // Test signout
  await session.signout();
  t.end();
});

test('data operations with validation', async (t) => {
  const pubky = Pubky.testnet();
  const keypair = Keypair.random();
  const homeserver = PublicKey.from('your_homeserver_public_key_here');

  const session = await pubky.signer(keypair).signup(homeserver, null);

  const pubkyId = keypair.publicKey.z32();
  const specs = new PubkySpecsBuilder(pubkyId);

  // Create and store validated post
  const postResult = specs.createPost("Test content", PubkyAppPostKind.Short, null, null, null);

  // PUT
  await session.storage.putJson(postResult.meta.path, postResult.post.toJson());

  // GET
  const retrieved = await session.storage.getJson(postResult.meta.path);
  t.equal(retrieved.content, "Test content", 'content matches');

  // DELETE
  await session.storage.delete(postResult.meta.path);

  // Confirm gone — getJson throws on 404
  try {
    await session.storage.getJson(postResult.meta.path);
    t.fail('expected getJson to throw after delete');
  } catch {
    t.pass('resource not found after delete');
  }
  t.end();
});
```

## React Integration Pattern

```javascript
import { createContext, useContext, useEffect, useState } from 'react';
import { Pubky, Keypair, Session } from '@synonymdev/pubky';
import { PubkySpecsBuilder } from 'pubky-app-specs';

const PubkyContext = createContext();
const SESSION_KEY = 'pubky_session';

export function PubkyProvider({ children }) {
  const [pubky] = useState(() => Pubky.testnet());
  const [session, setSession] = useState(null);
  const [specs, setSpecs] = useState(null);

  // Restore an exported session on mount.
  useEffect(() => {
    const exported = localStorage.getItem(SESSION_KEY);
    if (!exported) return;
    pubky.restoreSession(exported)
      .then(setSession)
      .catch(() => localStorage.removeItem(SESSION_KEY));
  }, [pubky]);

  // Re-create the specs builder whenever the session changes.
  useEffect(() => {
    if (session) {
      setSpecs(new PubkySpecsBuilder(session.info.publicKey.z32()));
    } else {
      setSpecs(null);
    }
  }, [session]);

  async function signIn(keypair) {
    try {
      const next = await pubky.signer(keypair).signin();
      localStorage.setItem(SESSION_KEY, next.export());
      setSession(next);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async function signOut() {
    if (!session) return;
    await session.signout();
    localStorage.removeItem(SESSION_KEY);
    setSession(null);
  }

  const value = {
    pubky,
    session,
    currentUser: session?.info.publicKey ?? null,
    specs,
    signIn,
    signOut,
    isSignedIn: !!session,
    isReady: !!specs,
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
        pubky: () => Pubky.testnet(),
        homeserver: 'your_testnet_homeserver_key_here',
        relay: 'http://localhost:15412/inbox/'
      },

      production: {
        pubky: () => new Pubky(),
        homeserver: 'your_production_homeserver_key_here',
        relay: 'https://httprelay.pubky.app/inbox'
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
- Third-party app authorization flows, including auth-flow resume
- Event streams for indexing, backup, and sync
- Encrypted recovery files for key backup/restore
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
- Only `/pub/*` is reachable on the tenant API: `GET`/`HEAD` are public, `PUT`/`DELETE` require a session with a write capability; anything else (e.g. `/priv/*`) returns `403 Forbidden` regardless of capability. More granular permission models may be implemented in the future.
- Write operations require appropriate capabilities
- Homeserver records should be republished periodically
- Use testnet for development, mainnet for production
- Error handling is crucial for network resilience, especially `404`, `429`, auth failures, and PKARR failures
- Recovery files are encrypted with user passphrases; native `.sess` files are bearer credentials and must be treated like passwords
- Browser `session.export()` stores public session metadata and still depends on the homeserver auth cookie
- Data models are automatically validated and sanitized
- IDs and paths are generated following strict conventions

### Critical Implementation Notes
- Never mock or simulate Pubky functionality - only use documented APIs
- All examples are based on actual working implementations
- Homeserver endpoints must be resolved via Pkarr network
- Sessions contain capabilities that determine permissions
- Use `publicKey.toString()` for display `pubky<z32>` identifiers and `publicKey.z32()` for transport/storage raw z-base-32 identifiers
- Validate inputs with SDK constructors/helpers instead of hand-parsing keys or capability strings
- All data models follow the `/pub/pubky.app/` path convention
- Do not claim private storage, homeserver mirroring, backup restore, cloud backup, or two-way backup sync as shipped features

### Shipped vs Planned
- Shipped: public `/pub` storage, capability-scoped sessions, PKARR homeserver discovery, app specs, resumable auth flows, event streams, local Pubky Backup, and PostgreSQL-backed homeservers.
- Planned/future: private app storage roots, signed/guarded/encrypted data as general app primitives, homeserver mirroring, backup restore, cloud backup, and two-way backup sync.

## Development checklist
When creating new pubky projects make sure you follow the checklist:
### Essential Features
- Configuration management with validation
- Connectivity testing for homeservers and Nexus
- Debug logging with verbose option
- Robust error handling with categorization
- Session persistence across operations
- Auth-flow resume handling where browser refresh/app switch is possible
- Event-stream cursor persistence for sync/indexing/backup workflows
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