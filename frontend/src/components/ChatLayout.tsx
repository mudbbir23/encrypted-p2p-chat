/**
 * Chat Layout — the main application UI after authentication.
 * Renders sidebar (room list) + chat area.
 * Messages are encrypted with Double Ratchet (AES-256-GCM) via cryptoService.
 */
import { createSignal, For, onMount, Show, createEffect } from "solid-js";
import { useStore } from "@nanostores/solid";
import { cryptoService } from "../crypto/crypto-service";
import {
  authStore,
  roomsStore,
  messagesStore,
  activeRoomId,
  presenceStore,
  typingStore,
  setActiveRoom,
  setRooms,
  clearAuth,
  appendMessage,
  updateMessageDecrypted,
  type ChatMessage,
} from "../stores";
import { wsClient } from "../ws/client";
import { KeyStore } from "../crypto/key-store";

export default function ChatLayout() {
  const auth = useStore(authStore);
  const rooms = useStore(roomsStore);
  const activeRoom = useStore(activeRoomId);
  const messages = useStore(messagesStore);
  const presence = useStore(presenceStore);
  const typing = useStore(typingStore);

  onMount(async () => {
    const user = auth();
    if (!user) return;

    // 1. Check for identity keys — if missing, initialize them (needed for new devices/cleared DB)
    const keys = await KeyStore.getIdentityKeys();
    if (!keys) {
      console.warn("[Crypto] Missing identity keys. Initializing new encryption session...");
      try {
        const ikKeys = await cryptoService.generateAndStoreIdentityKeys();
        const spkKeys = await cryptoService.generateSignedPrekey();
        const opkKeys = await cryptoService.generateOneTimePrekeys(20);

        const keysPayload = {
          identity_key_x25519: ikKeys.x25519_public,
          identity_key_ed25519: ikKeys.ed25519_public,
          signed_prekey: spkKeys.public,
          signed_prekey_sig: spkKeys.signature,
          one_time_prekeys: opkKeys.map((k) => k.public),
        };

        const res = await fetch(`/api/auth/keys/${user.user_id}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(keysPayload),
        });

        if (!res.ok) throw new Error("Key upload failed");
        console.log("[Crypto] Encryption keys auto-initialized successfully.");
      } catch (err) {
        console.error("[Crypto] Failed to auto-initialize keys:", err);
      }
    }

    // 2. Connect WebSocket
    wsClient.connect(user.user_id, user.username);

    // Listen for incoming encrypted messages and decrypt them
    wsClient.on("encrypted_message", async (data) => {
      const msg = data as unknown as ChatMessage;
      const senderId = msg.sender_id;
      if (senderId === user.user_id) return; // skip self (ack handled separately)

      // 1. Immediately append the encrypted message to the UI
      msg.decrypted = false;
      appendMessage(msg.room_id, msg);

      // 2. Attempt to decrypt it in the background
      // cryptoService now updates the store internally on success/error
      await cryptoService.decrypt(
        senderId,
        msg.ciphertext,
        msg.nonce,
        msg.header,
        msg.ephemeral_pub_key,
        msg.id,
        msg.room_id
      );
    });

    // Fetch rooms
    try {
      const res = await fetch(`/api/rooms/user/${user.user_id}`);
      if (res.ok) {
        const data = await res.json();
        setRooms(data.rooms ?? []);
      }
    } catch {
      // Offline — rooms will load when connection restores
    }
  });

  // Auto-scroll to bottom on new messages
  createEffect(() => {
    const roomId = activeRoom();
    if (!roomId) return;
    const msgs = messages()[roomId];
    if (msgs?.length) {
      setTimeout(() => {
        const el = document.getElementById("messages-container");
        if (el) el.scrollTop = el.scrollHeight;
      }, 50);
    }
  });

  async function handleLogout() {
    wsClient.disconnect();
    await KeyStore.clearAll(); // Wipe ALL key material — not just session info
    clearAuth();
  }

  const [searchUsername, setSearchUsername] = createSignal("");
  const [searchError, setSearchError] = createSignal("");
  const [isSearching, setIsSearching] = createSignal(false);

  async function handleStartChat(e: Event) {
    if (e) e.preventDefault();
    const targetUsername = searchUsername().trim();
    if (!targetUsername) return;
    if (targetUsername.toLowerCase() === user().username.toLowerCase()) {
      setSearchError("Cannot chat with yourself.");
      return;
    }

    setIsSearching(true);
    setSearchError("");

    try {
      // Look up target user
      const userRes = await fetch(`/api/auth/users/${encodeURIComponent(targetUsername)}`);
      if (!userRes.ok) {
        throw new Error("User not found.");
      }
      const targetUser = await userRes.json();

      // Check if room already exists locally
      const existingRoom = rooms().find((r) => 
        !r.is_group && r.participant_ids.includes(targetUser.id)
      );

      if (existingRoom) {
        setActiveRoom(existingRoom.id);
        setSearchUsername("");
        return;
      }

      // Create new room
      const roomRes = await fetch("/api/rooms/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "", // 1:1 chat uses the peer name
          is_group: false,
          participant_ids: [user().user_id, targetUser.id],
        }),
      });

      if (!roomRes.ok) {
        throw new Error("Failed to create room.");
      }

      const newRoom = await roomRes.json();
      setRooms([...rooms(), newRoom]);
      setActiveRoom(newRoom.id);
      setSearchUsername("");
    } catch (err: any) {
      setSearchError(err.message || "Failed to start chat.");
    } finally {
      setIsSearching(false);
    }
  }

  const user = () => auth()!;
  const currentMessages = () => messages()[activeRoom() ?? ""] ?? [];
  const currentTyping = () => typing()[activeRoom() ?? ""] ?? new Set<string>();

  return (
    <div class="app-layout">
      {/* Sidebar */}
      <aside class="sidebar">
        <div class="sidebar-header">
          <div class="sidebar-logo">
            <div class="sidebar-logo-icon">🔐</div>
            <span class="sidebar-logo-text">E2E Chat</span>
            <span class="sidebar-logo-badge">E2EE</span>
          </div>

          <div class="user-info">
            <div class="user-avatar">
              {user().username[0].toUpperCase()}
              <div class="user-avatar-status" />
            </div>
            <div style={{ flex: 1, "min-width": 0 }}>
              <div class="user-name">{user().display_name || user().username}</div>
              <div class="user-status">● Online</div>
            </div>
            <button
              id="logout-btn"
              class="btn-icon"
              title="Sign out"
              onClick={handleLogout}
            >
              ⏻
            </button>
          </div>
        </div>

        <div class="sidebar-section-label" style={{ "margin-top": "16px", "margin-bottom": "8px" }}>Start New Chat</div>
        <form class="search-form" onSubmit={handleStartChat} style={{ padding: "0 16px", "margin-bottom": "16px", display: "flex", "flex-direction": "column", gap: "8px" }}>
          <div style={{ display: "flex", gap: "8px" }}>
            <input
              type="text"
              placeholder="Enter exact username..."
              value={searchUsername()}
              onInput={(e) => { setSearchUsername(e.currentTarget.value); setSearchError(""); }}
              style={{ flex: 1, padding: "8px", "border-radius": "6px", border: "1px solid var(--color-border)", background: "var(--color-bg)", color: "var(--color-text)" }}
              disabled={isSearching()}
            />
            <button
              type="submit"
              disabled={!searchUsername().trim() || isSearching()}
              style={{ padding: "8px 12px", "border-radius": "6px", background: "var(--color-primary)", color: "white", border: "none", cursor: "pointer" }}
            >
              {isSearching() ? "..." : "Chat"}
            </button>
          </div>
          <Show when={searchError()}>
            <div style={{ color: "var(--color-error)", "font-size": "12px" }}>{searchError()}</div>
          </Show>
        </form>

        <div class="sidebar-section-label">Conversations</div>

        <div class="conversations-list">
          <For each={rooms()}>
            {(room) => {
              const peerIds = room.participant_ids.filter((id) => id !== user().user_id);
              const name = room.name || `Chat ${peerIds[0]?.slice(0, 8) ?? ""}`;
              const peerStatus = () => presence()[peerIds[0]] ?? "offline";
              const isActive = () => activeRoom() === room.id;

              return (
                <div
                  class={`conversation-item${isActive() ? " active" : ""}`}
                  onClick={() => setActiveRoom(room.id)}
                >
                  <div class="conversation-avatar">
                    {name[0].toUpperCase()}
                    <Show when={peerStatus() === "online"}>
                      <div class="online-dot" />
                    </Show>
                  </div>
                  <div class="conversation-info">
                    <div class="conversation-name">{name}</div>
                    <div class="conversation-preview">
                      <span class="lock-icon">🔒</span>
                      <span>End-to-end encrypted</span>
                    </div>
                  </div>
                </div>
              );
            }}
          </For>

          <Show when={rooms().length === 0}>
            <div
              style={{
                "text-align": "center",
                padding: "32px 16px",
                color: "var(--color-text-muted)",
                "font-size": "13px",
                "line-height": "1.6",
              }}
            >
              No conversations yet.
              <br />
              Share your user ID to start chatting.
            </div>
          </Show>
        </div>

        <div class="sidebar-footer">
          <div class="security-badge">
            <span>🛡️</span>
            <span>Signal Protocol · Zero Knowledge</span>
          </div>
        </div>
      </aside>

      {/* Chat area */}
      <Show when={activeRoom()} fallback={<NoChatPlaceholder />}>
        <main class="chat-area">
          <ChatHeader
            roomId={activeRoom()!}
            rooms={rooms()}
            userId={user().user_id}
            presence={presence()}
          />

          <div class="messages-container" id="messages-container">
            <For each={currentMessages()}>
              {(msg) => (
                <MessageBubble
                  message={msg}
                  isSent={msg.sender_id === user().user_id}
                />
              )}
            </For>

            {/* Typing indicators */}
            <For each={[...currentTyping()]}>
              {(_uid) => (
                <div class="message-row received">
                  <div class="typing-indicator">
                    <div class="typing-dot" />
                    <div class="typing-dot" />
                    <div class="typing-dot" />
                  </div>
                </div>
              )}
            </For>
          </div>

          <MessageInput
            roomId={activeRoom()!}
            userId={user().user_id}
            rooms={rooms()}
          />
        </main>
      </Show>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function NoChatPlaceholder() {
  return (
    <div class="chat-area">
      <div class="no-chat-screen">
        <div class="no-chat-graphic">🔐</div>
        <h2 class="no-chat-title">Select a Conversation</h2>
        <p class="no-chat-text">
          Choose a conversation from the sidebar to start chatting.
          All messages are end-to-end encrypted using the Signal Protocol —
          the server never sees your plaintext messages.
        </p>
      </div>
    </div>
  );
}

function ChatHeader(props: {
  roomId: string;
  rooms: any[];
  userId: string;
  presence: Record<string, string>;
}) {
  const room = () => props.rooms.find((r) => r.id === props.roomId);
  const peerIds = () =>
    (room()?.participant_ids ?? []).filter((id: string) => id !== props.userId);
  const name = () =>
    room()?.name || `Chat ${peerIds()[0]?.slice(0, 8) ?? "Unknown"}`;
  const status = () => props.presence[peerIds()[0]] ?? "offline";

  return (
    <div class="chat-header">
      <div class="chat-header-avatar">
        {name()[0].toUpperCase()}
      </div>
      <div class="chat-header-info">
        <div class="chat-header-name">{name()}</div>
        <div class="chat-header-status">
          <Show when={status() === "online"}>
            <span class="status-dot" />
            Online
          </Show>
          <Show when={status() !== "online"}>
            <span
              class="status-dot"
              style={{ background: "var(--color-text-muted)" }}
            />
            {status() === "away" ? "Away" : "Offline"}
          </Show>
        </div>
      </div>
      <div class="e2e-badge">
        <span>🔒</span>
        <span>End-to-end encrypted</span>
      </div>
    </div>
  );
}

function MessageBubble(props: { message: ChatMessage; isSent: boolean }) {
  const msg = props.message;
  const time = () =>
    new Date(msg.timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });

  return (
    <div class={`message-row ${props.isSent ? "sent" : "received"}`}>
      <Show when={!props.isSent}>
        <div class="message-sender">{msg.sender_username}</div>
      </Show>
      <div class={`message-bubble ${!msg.decrypted ? "encrypted-preview" : ""} ${msg.error ? "decrypt-error" : ""}`}>
        {msg.decrypted ? (
          msg.plaintext
        ) : (
          <div class="encrypted-content">
            <span class="lock-icon">🔒</span>
            <span class="cipher-text">{msg.ciphertext.slice(0, 20)}…</span>
            {msg.error && <div class="error-badge">{msg.error}</div>}
          </div>
        )}
      </div>
      <div class="message-meta">
        <span class="message-time">{time()}</span>
        <Show when={props.isSent && msg.decrypted}>
          <span class="message-status">✓✓</span>
        </Show>
      </div>
    </div>
  );
}

function MessageInput(props: {
  roomId: string;
  userId: string;
  rooms: any[];
}) {
  const [text, setText] = createSignal("");
  const [sending, setSending] = createSignal(false);
  const [error, setError] = createSignal("");

  const room = () => props.rooms.find((r) => r.id === props.roomId);
  const recipientId = () =>
    (room()?.participant_ids ?? []).find((id: string) => id !== props.userId) ?? "";

  let typingTimeout: ReturnType<typeof setTimeout>;

  function handleInput(e: InputEvent) {
    const val = (e.currentTarget as HTMLTextAreaElement).value;
    setText(val);
    setError("");
    wsClient.sendTyping(props.roomId, true);
    clearTimeout(typingTimeout);
    typingTimeout = setTimeout(() => {
      wsClient.sendTyping(props.roomId, false);
    }, 2000);
  }

  async function handleSend() {
    const content = text().trim();
    if (!content || sending()) return;
    setSending(true);
    clearTimeout(typingTimeout);
    wsClient.sendTyping(props.roomId, false);

    try {
      // Encrypt with Double Ratchet (or fall back gracefully on first message
      // before X3DH is complete — for local dev without server)
      let ciphertext: string;
      let nonce: string;
      let header: string;
      let ephemeralPubKey: string | undefined;

      try {
        const result = await cryptoService.encrypt(recipientId(), content);
        ciphertext = result.ciphertext;
        nonce = result.nonce;
        header = result.header;
        ephemeralPubKey = result.ephemeralPubKey;
      } catch (err: any) {
        console.error("[Crypto] Encryption failed:", err);
        setError(err.message || "Encryption failed");
        setSending(false);
        return;
      }

      const tempId = crypto.randomUUID();

      // Optimistically render our own message as decrypted
      appendMessage(props.roomId, {
        id: `temp-${tempId}`,
        room_id: props.roomId,
        sender_id: props.userId,
        sender_username: "You",
        ciphertext,
        nonce,
        header,
        decrypted: true,
        plaintext: content,
        timestamp: new Date().toISOString(),
        temp_id: tempId,
      });

      wsClient.sendEncryptedMessage(
        recipientId(),
        props.roomId,
        ciphertext,
        nonce,
        header,
        tempId,
        ephemeralPubKey
      );

      setText("");
    } catch (err: any) {
      setError(err.message || "Failed to send");
    } finally {
      setSending(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  return (
    <div class="message-input-area">
      <Show when={error()}>
        <div style={{ color: "var(--color-error)", "font-size": "12px", "margin-bottom": "8px", "text-align": "center" }}>
          {error()}
        </div>
      </Show>
      <div class="message-input-container">
        <textarea
          id="message-input"
          class="message-input"
          placeholder="Send an encrypted message… (Enter to send)"
          rows={1}
          value={text()}
          onInput={handleInput}
          onKeyDown={handleKeyDown}
          disabled={!recipientId() || sending()}
        />
        <button
          id="send-message-btn"
          class="send-btn"
          onClick={handleSend}
          disabled={!text().trim() || !recipientId() || sending()}
          title="Send encrypted message"
        >
          <Show when={sending()} fallback="↑">
            <div class="spinner" style={{ width: "16px", height: "16px", "border-width": "2px" }} />
          </Show>
        </button>
      </div>
      <div class="input-footer">
        <span>🔒</span>
        <span>AES-256-GCM · Signal Double Ratchet · Zero-knowledge relay</span>
      </div>
    </div>
  );
}
