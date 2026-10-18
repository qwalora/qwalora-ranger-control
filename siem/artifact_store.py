"""F3 - provider-neutral secure evidence object storage.

An `ArtifactStore` holds large/binary evidence bytes OUTSIDE Postgres/OpenSearch. Objects are
immutable and content-addressed (key = `blob/<sha256>`); the store computes the SHA-256 itself
while streaming, so a candidate-supplied hash is never trusted. Writes are atomic: an
interrupted or oversized upload leaves NO visible object. Objects are private (never served
directly to a candidate); retrieval goes through Ranger server-side authorization elsewhere.

Two adapters share one contract:
  - `FilesystemArtifactStore` - deterministic dev/test backend with strict path containment.
  - `S3ArtifactStore` - S3-compatible, driven by an INJECTED client (put/get/head/delete/
    presign). No bucket is provisioned and no network call is made here; inject a client at
    deploy time (or a fake in tests). This keeps future S3 deployment a config change, not a
    redesign.

Nothing in this module executes uploaded content, decompresses archives, or renders media.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import uuid

_KEY_RE = re.compile(r"^blob/[0-9a-f]{64}$")
_DEFAULT_MAX = 1024 * 1024 * 1024   # 1 GiB hard ceiling; callers pass a tighter per-type cap


class StorageError(Exception):
    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class PutResult:
    def __init__(self, key, sha256, size, media_type, scan_state="unscanned", created=True):
        self.key = key; self.sha256 = sha256; self.size = size
        self.media_type = media_type; self.scan_state = scan_state
        # created=True iff this call actually wrote NEW bytes; False means the object already
        # existed (content-addressed dedup hit). Callers must never physically delete a dedup hit
        # on rollback - those bytes may belong to another artifact/tenant.
        self.created = created

    def as_dict(self):
        return {"key": self.key, "sha256": self.sha256, "size": self.size,
                "media_type": self.media_type, "scan_state": self.scan_state,
                "created": self.created}


class StagedObject:
    """A computed-but-unpublished object. Its content hash (and therefore its final content-addressed
    key) is known, but the bytes are NOT yet visible in the store. Publication is deferred to
    `commit()` so a caller can take the per-object lock BEFORE the bytes become visible, closing the
    race where an object is published to the store before its durable reference is registered (a
    concurrent sweep could otherwise delete freshly-published, not-yet-referenced bytes).

    Exactly one of commit()/discard() may be called; both are idempotent against a second call."""

    def __init__(self, store, key, sha256, size, media_type):
        self.store = store
        self.key = key
        self.sha256 = sha256
        self.size = size
        self.media_type = media_type
        self._done = False

    def commit(self) -> "PutResult":
        """Publish the staged bytes (atomic; a content-addressed dedup hit publishes nothing and
        reports created=False). Returns a PutResult identical to put_stream's."""
        if self._done:
            raise StorageError("ALREADY_FINALIZED", "staged object already finalized")
        self._done = True
        return self.store._publish_staged(self)

    def discard(self):
        """Drop the staged (unpublished) bytes without publishing. Safe no-op if already finalized."""
        if self._done:
            return
        self._done = True
        self.store._discard_staged(self)


# --- server-side file-signature sniffing (magic bytes, never the declared type) ---
def sniff_media_type(head: bytes) -> str:
    h = head
    if h[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if h[:2] == b"II" and h[2:4] == b"\x2a\x00" or h[:2] == b"MM" and h[2:4] == b"\x00\x2a":
        return "image/tiff"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return "image/webp"
    if h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return "audio/wav"
    if h[:4] == b"\x1aE\xdf\xa3":
        return "video/x-matroska"      # also webm (EBML)
    if h[4:8] == b"ftyp":
        brand = h[8:12]
        if brand in (b"qt  ",):
            return "video/quicktime"
        if brand[:3] in (b"M4A", b"M4B"):
            return "audio/mp4"
        return "video/mp4"
    if h[:3] == b"ID3" or h[:2] == b"\xff\xfb":
        return "audio/mpeg"
    if h[:4] == b"fLaC":
        return "audio/flac"
    if h[:4] == b"OggS":
        return "audio/ogg"
    if h[:4] == b"%PDF":
        return "application/pdf"
    if h[:2] == b"PK":
        return "application/zip"       # archive - caller decides; never auto-decompressed
    if h[:1] in (b"{", b"["):
        return "application/json"
    return "application/octet-stream"


def _read_hash_size(fileobj, max_bytes, chunk, sink):
    """Stream fileobj -> sink(callable(bytes)), computing sha256 + size, enforcing max_bytes.
    Returns (sha256_hex, size, head32). Raises StorageError on overflow. Propagates read errors
    (interrupted stream) so the caller can abort atomically."""
    h = hashlib.sha256(); size = 0; head = b""
    while True:
        b = fileobj.read(chunk)
        if not b:
            break
        size += len(b)
        if size > max_bytes:
            raise StorageError("TOO_LARGE", f"upload exceeds {max_bytes} bytes")
        if len(head) < 32:
            head += b[:32 - len(head)]
        h.update(b)
        sink(b)
    return h.hexdigest(), size, head


class ArtifactStore:
    """Abstract contract. All adapters are content-addressed + immutable + private."""

    def put_stream(self, fileobj, *, max_bytes=_DEFAULT_MAX, allowed_media_types=None,
                   chunk=65536) -> PutResult:
        """One-shot: stage the stream and publish it immediately. Equivalent to
        stage_stream(...).commit(); kept as the simple path for callers that do not need to take a
        per-object lock between hashing and publication."""
        return self.stage_stream(fileobj, max_bytes=max_bytes,
                                 allowed_media_types=allowed_media_types, chunk=chunk).commit()

    def stage_stream(self, fileobj, *, max_bytes=_DEFAULT_MAX, allowed_media_types=None,
                     chunk=65536) -> "StagedObject":
        """Stream + hash + sniff + validate the bytes WITHOUT publishing them, returning a
        StagedObject whose final key is known. The caller publishes with .commit() (ideally under a
        per-object lock) or drops with .discard()."""
        raise NotImplementedError

    def _publish_staged(self, staged) -> "PutResult":
        raise NotImplementedError

    def _discard_staged(self, staged):
        raise NotImplementedError

    def open_stream(self, key):
        raise NotImplementedError

    def get_bytes(self, key) -> bytes:
        with self.open_stream(key) as f:
            return f.read()

    def exists(self, key) -> bool:
        raise NotImplementedError

    def verify(self, key, expected_sha256) -> bool:
        """Independently re-read the stored bytes and confirm the digest (integrity check)."""
        if not self.exists(key):
            return False
        h = hashlib.sha256()
        with self.open_stream(key) as f:
            for b in iter(lambda: f.read(65536), b""):
                h.update(b)
        return h.hexdigest() == expected_sha256

    def delete(self, key, *, authorized_reason) -> bool:
        raise NotImplementedError

    def presign(self, key, *, operation="get", ttl_seconds=300):
        """Return a scoped, short-lived access grant descriptor, or None if unsupported.
        Revocation note: an already-issued presigned grant CANNOT be revoked before its TTL
        expires without rotating the underlying credential/policy; keep TTLs short."""
        return None

    @staticmethod
    def _validate_key(key):
        if not isinstance(key, str) or not _KEY_RE.match(key):
            raise StorageError("BAD_KEY", "object key must be blob/<sha256>")


def _finalize_media(detected, allowed_media_types):
    if allowed_media_types is not None and detected not in allowed_media_types:
        raise StorageError("UNSUPPORTED_MEDIA", f"detected media type {detected!r} not allowed")


class FilesystemArtifactStore(ArtifactStore):
    """Deterministic development/test backend. Objects live under <root>/blob (private, 0600),
    temp writes under <root>/tmp. Path containment is strict; keys are content-addressed."""

    def __init__(self, root):
        self.root = os.path.realpath(root)
        self._blob = os.path.join(self.root, "blob")
        self._tmp = os.path.join(self.root, "tmp")
        os.makedirs(self._blob, exist_ok=True)
        os.makedirs(self._tmp, exist_ok=True)

    def _path(self, key):
        self._validate_key(key)
        p = os.path.realpath(os.path.join(self.root, key))
        # containment: resolved path must stay under <root>/blob
        if not (p == self._blob or p.startswith(self._blob + os.sep)):
            raise StorageError("PATH_ESCAPE", "resolved object path escapes the store root")
        return p

    def stage_stream(self, fileobj, *, max_bytes=_DEFAULT_MAX, allowed_media_types=None, chunk=65536):
        tmp = os.path.join(self._tmp, uuid.uuid4().hex)
        f = open(tmp, "wb")
        try:
            sha, size, head = _read_hash_size(fileobj, max_bytes, chunk, f.write)
            f.flush(); os.fsync(f.fileno()); f.close()
            media = sniff_media_type(head)
            _finalize_media(media, allowed_media_types)
        except BaseException:
            try:
                if not f.closed:
                    f.close()
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)                   # interrupted/oversized -> nothing left behind
            raise
        staged = StagedObject(self, f"blob/{sha}", sha, size, media)
        staged._tmp = tmp                            # the hashed bytes, held unpublished under <root>/tmp
        return staged

    def _publish_staged(self, staged):
        tmp = getattr(staged, "_tmp", None)
        try:
            final = self._path(staged.key)
            if os.path.exists(final):
                if tmp and os.path.exists(tmp):
                    os.remove(tmp)                   # dedup: identical content already stored
                created = False
            else:
                os.chmod(tmp, 0o600)
                os.replace(tmp, final)               # atomic publish; no partial object ever visible
                dfd = os.open(self._blob, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
                created = True
            return PutResult(staged.key, staged.sha256, staged.size, staged.media_type,
                             scan_state="unscanned", created=created)
        except BaseException:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
            raise

    def _discard_staged(self, staged):
        tmp = getattr(staged, "_tmp", None)
        if tmp and os.path.exists(tmp):
            os.remove(tmp)

    def open_stream(self, key):
        p = self._path(key)
        if not os.path.exists(p):
            raise StorageError("NOT_FOUND", "object does not exist")
        return open(p, "rb")

    def exists(self, key):
        try:
            return os.path.exists(self._path(key))
        except StorageError:
            return False

    def delete(self, key, *, authorized_reason):
        if not authorized_reason:
            raise StorageError("UNAUTHORIZED_DELETE", "deletion requires an authorized reason")
        p = self._path(key)
        if os.path.exists(p):
            os.remove(p)
            return True
        return False


class S3ArtifactStore(ArtifactStore):
    """S3-compatible adapter driven by an injected client (boto3 S3 client or any object with
    put_object/get_object/head_object/delete_object and optional generate_presigned_url). No
    bucket is provisioned and no network call is made in this module; inject a configured client
    at deploy time, or a fake in tests. Same content-addressed + server-hash + size-cap contract."""

    def __init__(self, bucket, client=None, *, prefix=""):
        self.bucket = bucket
        self.client = client
        self.prefix = prefix

    def _require_client(self):
        if self.client is None:
            raise StorageError("NOT_PROVISIONED",
                               "no S3 client injected; object storage is not provisioned")
        return self.client

    def _okey(self, key):
        self._validate_key(key)
        return f"{self.prefix}{key}" if self.prefix else key

    def stage_stream(self, fileobj, *, max_bytes=_DEFAULT_MAX, allowed_media_types=None, chunk=65536):
        self._require_client()
        buf = io.BytesIO()
        sha, size, head = _read_hash_size(fileobj, max_bytes, chunk, buf.write)
        media = sniff_media_type(head)
        _finalize_media(media, allowed_media_types)
        staged = StagedObject(self, f"blob/{sha}", sha, size, media)
        staged._buf = buf                            # hashed bytes buffered, not yet put to the bucket
        return staged

    def _publish_staged(self, staged):
        client = self._require_client()
        okey = self._okey(staged.key)
        # content-addressed + immutable: skip if the object already exists (dedup)
        exists = True
        try:
            client.head_object(Bucket=self.bucket, Key=okey)
        except Exception:
            exists = False
        if not exists:
            staged._buf.seek(0)
            client.put_object(Bucket=self.bucket, Key=okey, Body=staged._buf.getvalue())
        staged._buf = None
        return PutResult(staged.key, staged.sha256, staged.size, staged.media_type,
                         scan_state="unscanned", created=not exists)

    def _discard_staged(self, staged):
        staged._buf = None

    def open_stream(self, key):
        client = self._require_client()
        try:
            resp = client.get_object(Bucket=self.bucket, Key=self._okey(key))
        except Exception as e:
            raise StorageError("NOT_FOUND", f"object not retrievable: {e}")
        body = resp["Body"]
        data = body.read() if hasattr(body, "read") else body
        return io.BytesIO(data if isinstance(data, bytes) else bytes(data))

    def exists(self, key):
        client = self._require_client()
        try:
            client.head_object(Bucket=self.bucket, Key=self._okey(key))
            return True
        except Exception:
            return False

    def delete(self, key, *, authorized_reason):
        if not authorized_reason:
            raise StorageError("UNAUTHORIZED_DELETE", "deletion requires an authorized reason")
        client = self._require_client()
        client.delete_object(Bucket=self.bucket, Key=self._okey(key))
        return True

    def presign(self, key, *, operation="get", ttl_seconds=300):
        client = self._require_client()
        okey = self._okey(key)
        op = {"get": "get_object", "put": "put_object"}.get(operation)
        if op is None:
            raise StorageError("BAD_OPERATION", f"unsupported presign operation {operation!r}")
        if not hasattr(client, "generate_presigned_url"):
            # interface contract honored; concrete URL generation is a deploy-time client concern
            return {"supported": False, "operation": operation, "key": okey,
                    "ttl_seconds": ttl_seconds,
                    "revocation": "a presigned URL cannot be revoked before TTL expiry without "
                                  "rotating the credential/policy; keep TTLs short"}
        url = client.generate_presigned_url(op, Params={"Bucket": self.bucket, "Key": okey},
                                            ExpiresIn=ttl_seconds)
        return {"supported": True, "url": url, "operation": operation, "key": okey,
                "ttl_seconds": ttl_seconds,
                "revocation": "cannot be revoked before TTL expiry without credential/policy rotation"}
