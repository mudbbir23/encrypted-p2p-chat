/**
 * WebSocket client for real-time encrypted messaging.
 *
 * Manages:
 * - Connection lifecycle (connect, auto-reconnect, disconnect)
 * - Inbound message dispatch → store updates
 * - Outbound message sending with typed payloads
 * - Heartbeat ping/pong
 */
import {
  appendMessage,
  setPresence,
  setTyping,
  type ChatMessage,
} from "../stores";

const WS_URL =
  typeof window !== "undefined"
    ? `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws`
    : "ws://localhost:8000/ws";

const RECONNECT_DELAY_MS = 3000;
const MAX_RECONNECT_ATTEMPTS = 10;

type MessageHandler = (data: Record<string, unknown>) => void;

class WebSocketClient {
  private ws: WebSocket | null = null;
  private userId: string | null = null;
  private username: string | null = null;
  private reconnectAttempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private handlers: Map<string, MessageHandler[]> = new Map();
  private isDestroyed = false;

  connect(userId: string, username: string): void {
    this.userId = userId;
    this.username = username;
    this.isDestroyed = false;
    this._connect();
  }

  disconnect(): void {
    this.isDestroyed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    if (this.ws) {
      this.ws.close(1000, "Intentional disconnect");
      this.ws = null;
    }
  }

  private _connect(): void {
    if (!this.userId || !this.username) return;

    const url = `${WS_URL}?user_id=${encodeURIComponent(this.userId)}&username=${encodeURIComponent(this.username)}`;
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      console.info("[WS] Connected");
      this.reconnectAttempts = 0;
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data as string) as Record<string, unknown>;
        this._dispatch(data);
      } catch {
        console.warn("[WS] Failed to parse message:", event.data);
      }
    };

    this.ws.onclose = (event) => {
      console.info("[WS] Disconnected:", event.code, event.reason);
      if (!this.isDestroyed && this.reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
        this.reconnectAttempts++;
        this.reconnectTimer = setTimeout(
          () => this._connect(),
          RECONNECT_DELAY_MS * Math.min(this.reconnectAttempts, 5)
        );
      }
    };

    this.ws.onerror = (err) => {
      console.error("[WS] Error:", err);
    };
  }

  private _dispatch(data: Record<string, unknown>): void {
    const type = data.type as string;
    if (!type) return;

    // Update stores
    switch (type) {
      case "encrypted_message": {
        // We no longer append here to avoid duplication with ChatLayout
        break;
      }
      case "typing": {
        const userId = data.user_id as string;
        const roomId = data.room_id as string;
        const isTyping = data.is_typing as boolean;
        setTyping(roomId, userId, isTyping);
        break;
      }
      case "presence": {
        setPresence(
          data.user_id as string,
          data.status as "online" | "offline" | "away"
        );
        break;
      }
      case "pong":
        // Heartbeat acknowledged
        break;
    }

    // Custom handlers
    const handlers = this.handlers.get(type);
    if (handlers) {
      for (const h of handlers) {
        h(data);
      }
    }
  }

  on(type: string, handler: MessageHandler): () => void {
    const list = this.handlers.get(type) ?? [];
    list.push(handler);
    this.handlers.set(type, list);
    return () => {
      const updated = (this.handlers.get(type) ?? []).filter((h) => h !== handler);
      this.handlers.set(type, updated);
    };
  }

  send(payload: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(payload));
    }
  }

  sendEncryptedMessage(
    recipientId: string,
    roomId: string,
    ciphertext: string,
    nonce: string,
    header: string,
    tempId?: string,
    ephemeralPubKey?: string
  ): void {
    this.send({
      type: "encrypted_message",
      recipient_id: recipientId,
      room_id: roomId,
      ciphertext,
      nonce,
      header,
      temp_id: tempId,
      ephemeral_pub_key: ephemeralPubKey,
    });
  }

  sendTyping(roomId: string, isTyping: boolean): void {
    this.send({ type: "typing", room_id: roomId, is_typing: isTyping });
  }

  sendHeartbeat(): void {
    this.send({ type: "heartbeat" });
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

export const wsClient = new WebSocketClient();
