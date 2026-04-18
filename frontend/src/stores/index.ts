/**
 * Application state stores using nanostores.
 *
 * Stores:
 * - authStore: Current session (user_id, username)
 * - roomStore: List of chat rooms + active room
 * - messagesStore: Messages per room
 * - presenceStore: Online status per user
 * - typingStore: Typing indicators per room
 */
import { atom, map } from "nanostores";

// ---------------------------------------------------------------------------
// Auth Store
// ---------------------------------------------------------------------------

export interface AuthUser {
  user_id: string;
  username: string;
  display_name: string;
}

export const authStore = atom<AuthUser | null>(null);
export const isAuthenticated = atom<boolean>(false);

export function setAuth(user: AuthUser) {
  authStore.set(user);
  isAuthenticated.set(true);
}

export function clearAuth() {
  authStore.set(null);
  isAuthenticated.set(false);
}

// ---------------------------------------------------------------------------
// Room Store
// ---------------------------------------------------------------------------

export interface Room {
  id: string;
  name?: string;
  is_group: boolean;
  participant_ids: string[];
  last_message_at?: string;
}

export const roomsStore = atom<Room[]>([]);
export const activeRoomId = atom<string | null>(null);

export function setRooms(rooms: Room[]) {
  roomsStore.set(rooms);
}

export function setActiveRoom(id: string | null) {
  activeRoomId.set(id);
}

// ---------------------------------------------------------------------------
// Messages Store
// ---------------------------------------------------------------------------

export interface ChatMessage {
  id: string;
  room_id: string;
  sender_id: string;
  sender_username: string;
  // Encrypted fields (as-received from server/WebSocket)
  ciphertext: string;
  nonce: string;
  header: string;
  // Decrypted fields (populated after local decryption)
  plaintext?: string;
  decrypted: boolean;
  timestamp: string;
  temp_id?: string;
  ephemeral_pub_key?: string;
  error?: string;
}

// Map of room_id → ChatMessage[]
export const messagesStore = map<Record<string, ChatMessage[]>>({});

export function appendMessage(roomId: string, msg: ChatMessage) {
  const current = messagesStore.get();
  const roomMsgs = current[roomId] ?? [];
  messagesStore.setKey(roomId, [...roomMsgs, msg]);
}

export function updateMessageDecrypted(roomId: string, msgId: string, plaintext: string) {
  const current = messagesStore.get();
  const roomMsgs = current[roomId] ?? [];
  const updated = roomMsgs.map((m) =>
    m.id === msgId ? { ...m, plaintext, decrypted: true, error: undefined } : m
  );
  messagesStore.setKey(roomId, updated);
}

export function updateMessageError(roomId: string, msgId: string, error: string) {
  const current = messagesStore.get();
  const roomMsgs = current[roomId] ?? [];
  const updated = roomMsgs.map((m) =>
    m.id === msgId ? { ...m, error } : m
  );
  messagesStore.setKey(roomId, updated);
}

// ---------------------------------------------------------------------------
// Presence Store
// ---------------------------------------------------------------------------

export type PresenceStatus = "online" | "offline" | "away";

export const presenceStore = map<Record<string, PresenceStatus>>({});

export function setPresence(userId: string, status: PresenceStatus) {
  presenceStore.setKey(userId, status);
}

// ---------------------------------------------------------------------------
// Typing Store
// ---------------------------------------------------------------------------

// Map of room_id → Set of user_ids currently typing
export const typingStore = map<Record<string, Set<string>>>({});

export function setTyping(roomId: string, userId: string, isTyping: boolean) {
  const current = typingStore.get();
  const typing = new Set(current[roomId] ?? []);

  if (isTyping) {
    typing.add(userId);
  } else {
    typing.delete(userId);
  }

  typingStore.setKey(roomId, typing);
}
