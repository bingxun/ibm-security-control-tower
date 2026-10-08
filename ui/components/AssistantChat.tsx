"use client";

import { useEffect, useRef, useState } from "react";
import { useAuth } from "@/lib/auth";
import { sendChat, type ChatMessage } from "@/lib/api";
import MiniMarkdown from "./MiniMarkdown";

const GREETING: ChatMessage = {
  role: "assistant",
  content: "Hi — I'm the Control Tower assistant. I can explain how the review workflow works, your roles and features, or answer questions about the CVEs in your workspace. I stick to this product and your findings.",
};
const SUGGESTIONS = [
  "How does the review workflow work?",
  "What needs my action?",
  "Explain the finding statuses",
];

function runIdFromUrl(): string | undefined {
  if (typeof window === "undefined") return undefined;
  return new URLSearchParams(window.location.search).get("run") ?? undefined;
}

const OPEN_KEY = "ct-chat-open";
const MSGS_KEY = "ct-chat-msgs";

export default function AssistantChat() {
  const { user } = useAuth();
  const [open, setOpen] = useState<boolean>(() => {
    try { return sessionStorage.getItem(OPEN_KEY) === "1"; } catch { return false; }
  });
  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    try {
      const saved = sessionStorage.getItem(MSGS_KEY);
      if (saved) { const p = JSON.parse(saved); if (Array.isArray(p) && p.length) return p; }
    } catch { /* ignore */ }
    return [GREETING];
  });
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, loading, open]);

  // Persist across navigation (component stays mounted in the layout) and reloads.
  useEffect(() => { try { sessionStorage.setItem(OPEN_KEY, open ? "1" : "0"); } catch { /* ignore */ } }, [open]);
  useEffect(() => { try { sessionStorage.setItem(MSGS_KEY, JSON.stringify(messages)); } catch { /* ignore */ } }, [messages]);

  if (!user) return null;

  const send = async (text: string) => {
    const content = text.trim();
    if (!content || loading) return;
    const next = [...messages, { role: "user" as const, content }];
    setMessages(next);
    setInput("");
    setLoading(true);
    try {
      // Send only the real exchange (drop the leading canned greeting) for grounding.
      const history = next[0]?.role === "assistant" && next[0]?.content === GREETING.content ? next.slice(1) : next;
      const { reply } = await sendChat(history, runIdFromUrl());
      setMessages((m) => [...m, { role: "assistant", content: reply }]);
    } catch {
      setMessages((m) => [...m, { role: "assistant", content: "I couldn't reach the assistant just now. Please try again in a moment." }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Floating launcher */}
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Open assistant"
        className="fixed bottom-6 right-6 z-[90] grid place-items-center w-14 h-14 rounded-full transition-transform hover:scale-105 active:scale-95"
        style={{ background: "var(--brand-grad)", boxShadow: "0 10px 30px -6px rgba(232,84,63,0.5), var(--shadow-card)", color: "#fff" }}
      >
        {open ? (
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
        ) : (
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /><path d="M8 9h8M8 13h5" /></svg>
        )}
      </button>

      {open && (
        <div
          className="fixed bottom-24 right-6 z-[90] w-[380px] max-w-[calc(100vw-2rem)] rounded-2xl overflow-hidden flex flex-col ct-fade-up"
          style={{ height: "min(560px, calc(100vh - 8rem))", background: "var(--surface)", border: "1px solid var(--border2)", boxShadow: "var(--shadow-pop)" }}
        >
          {/* Header */}
          <div className="flex items-center gap-3 px-4 py-3 flex-shrink-0" style={{ borderBottom: "1px solid var(--border)", background: "var(--surface2)" }}>
            <span className="grid place-items-center w-8 h-8 rounded-lg flex-shrink-0" style={{ background: "var(--brand-grad)", color: "#fff" }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" /></svg>
            </span>
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-bold leading-none" style={{ color: "var(--heading)" }}>Control Tower Assistant</div>
              <div className="text-[11px] leading-none mt-1" style={{ color: "var(--muted)" }}>Product &amp; vulnerability help</div>
            </div>
            <button onClick={() => setOpen(false)} aria-label="Close" className="w-7 h-7 grid place-items-center rounded-lg transition-opacity hover:opacity-70" style={{ background: "var(--surface3)", color: "var(--muted)" }}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
            </button>
          </div>

          {/* Messages */}
          <div ref={scrollRef} className="flex-1 min-h-0 overflow-y-auto px-4 py-4 flex flex-col gap-3">
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                <div
                  className={`max-w-[85%] px-3.5 py-2.5 rounded-2xl text-[13px] leading-relaxed break-words ${m.role === "user" ? "whitespace-pre-wrap" : ""}`}
                  style={m.role === "user"
                    ? { background: "var(--accent-blue)", color: "#fff", borderBottomRightRadius: "6px" }
                    : { background: "var(--surface2)", color: "var(--body)", border: "1px solid var(--border)", borderBottomLeftRadius: "6px" }}
                >
                  {m.role === "user" ? m.content : <MiniMarkdown text={m.content} />}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="px-4 py-3 rounded-2xl flex items-center gap-1.5" style={{ background: "var(--surface2)", border: "1px solid var(--border)" }}>
                  {[0, 1, 2].map((d) => (
                    <span key={d} className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ background: "var(--muted)", animationDelay: `${d * 0.15}s` }} />
                  ))}
                </div>
              </div>
            )}
            {messages.length === 1 && !loading && (
              <div className="flex flex-col gap-2 mt-1">
                {SUGGESTIONS.map((s) => (
                  <button key={s} onClick={() => send(s)} className="text-left text-[12px] px-3 py-2 rounded-xl transition-colors hover:opacity-80"
                    style={{ background: "var(--surface3)", border: "1px solid var(--border)", color: "var(--subtle)" }}>
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Composer */}
          <div className="px-3 py-3 flex-shrink-0" style={{ borderTop: "1px solid var(--border)" }}>
            <div className="flex items-end gap-2">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input); } }}
                rows={1}
                placeholder="Ask about Control Tower or a CVE…"
                className="flex-1 resize-none outline-none px-3 py-2 rounded-xl text-[13px] max-h-28"
                style={{ background: "var(--surface2)", border: "1px solid var(--border)", color: "var(--body)" }}
              />
              <button
                onClick={() => send(input)}
                disabled={!input.trim() || loading}
                aria-label="Send"
                className="grid place-items-center w-9 h-9 rounded-xl flex-shrink-0 transition-opacity"
                style={{ background: input.trim() && !loading ? "var(--accent-blue)" : "var(--surface3)", color: input.trim() && !loading ? "#fff" : "var(--dim)", cursor: input.trim() && !loading ? "pointer" : "not-allowed" }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>
              </button>
            </div>
            <p className="text-[10px] mt-1.5 text-center" style={{ color: "var(--dim)" }}>Scoped to Control Tower &amp; your workspace findings · advisory only</p>
          </div>
        </div>
      )}
    </>
  );
}
