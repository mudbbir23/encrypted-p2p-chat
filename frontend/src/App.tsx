/**
 * Root App component — renders Auth screen or Chat UI based on session.
 */
import { createSignal, onMount, Show } from "solid-js";
import { authStore, isAuthenticated, setAuth } from "./stores";
import { useStore } from "@nanostores/solid";
import { KeyStore } from "./crypto/key-store";
import AuthScreen from "./components/AuthScreen";
import ChatLayout from "./components/ChatLayout";

export default function App() {
  const auth = useStore(isAuthenticated);
  const [loading, setLoading] = createSignal(true);

  onMount(async () => {
    // Restore session from IndexedDB on page load
    try {
      const session = await KeyStore.getSessionInfo();
      if (session) {
        setAuth({
          user_id: session.user_id,
          username: session.username,
          display_name: session.display_name,
        });
      }
    } catch {
      // No session or IndexedDB error — stay on auth screen
    } finally {
      setLoading(false);
    }
  });

  return (
    <Show when={!loading()} fallback={<AppLoader />}>
      <Show when={auth()} fallback={<AuthScreen />}>
        <ChatLayout />
      </Show>
    </Show>
  );
}

function AppLoader() {
  return (
    <div
      style={{
        display: "flex",
        "align-items": "center",
        "justify-content": "center",
        height: "100vh",
        background: "var(--color-bg-base)",
        gap: "12px",
      }}
    >
      <div class="spinner" style={{ width: "32px", height: "32px", "border-width": "3px" }} />
    </div>
  );
}
