import React, { useState, useEffect, useRef } from 'react';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

interface Conversation {
  id: number;
  title: string;
  created_at: string;
  message_count: number;
}

export default function CopilotPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [conversationId, setConversationId] = useState<number | null>(null);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [configured, setConfigured] = useState(true);
  const [showHistory, setShowHistory] = useState(false);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [addonEnabled, setAddonEnabled] = useState<boolean | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Check if AI Copilot add-on is enabled for this tenant
  useEffect(() => {
    if (!open) return;
    fetch('/api/tenant/config')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) { setAddonEnabled(true); return; } // no config = allow
        const plan = data.plan || 'free';
        // Enterprise includes everything; otherwise check add-on toggle
        if (plan === 'enterprise') {
          setAddonEnabled(true);
        } else {
          setAddonEnabled(!!data.addons?.ai_copilot);
        }
      })
      .catch(() => setAddonEnabled(true)); // on error, allow access
  }, [open]);

  useEffect(() => {
    if (open && addonEnabled) {
      fetchSuggestions();
      inputRef.current?.focus();
    }
  }, [open, addonEnabled]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function fetchSuggestions() {
    try {
      const res = await fetch('/api/copilot/suggestions');
      if (res.ok) {
        const data = await res.json();
        setSuggestions(data.suggestions || []);
        setConfigured(data.configured !== false);
      }
    } catch { /* ignore */ }
  }

  async function fetchHistory() {
    try {
      const res = await fetch('/api/copilot/conversations?limit=20');
      if (res.ok) {
        const data = await res.json();
        setConversations(data.conversations || []);
      }
    } catch { /* ignore */ }
  }

  async function sendMessage(text?: string) {
    const msg = (text || input).trim();
    if (!msg || loading) return;

    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: msg }]);
    setLoading(true);

    try {
      const res = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg, conversation_id: conversationId }),
      });
      const data = await res.json();
      if (data.error === 'not_configured') {
        setConfigured(false);
      }
      setMessages(prev => [...prev, { role: 'assistant', content: data.response || data.error || 'No response' }]);
      if (data.conversation_id) setConversationId(data.conversation_id);
      if (data.suggestions) setSuggestions(data.suggestions);
    } catch (e: any) {
      setMessages(prev => [...prev, { role: 'assistant', content: `Error: ${e?.message || 'Failed to reach copilot'}` }]);
    } finally {
      setLoading(false);
    }
  }

  function startNewChat() {
    setMessages([]);
    setConversationId(null);
    setShowHistory(false);
    fetchSuggestions();
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  function renderMarkdown(text: string) {
    // Simple markdown: bold, inline code, bullet lists
    return text.split('\n').map((line, i) => {
      const processed = line
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.*?)`/g, '<code class="px-1 py-0.5 bg-gray-200 dark:bg-slate-600 rounded text-xs">$1</code>');
      if (line.startsWith('- ') || line.startsWith('* ')) {
        return <li key={i} className="ml-4 list-disc text-sm" dangerouslySetInnerHTML={{ __html: processed.slice(2) }} />;
      }
      if (line.startsWith('### ')) {
        return <h4 key={i} className="font-semibold text-sm mt-2">{line.slice(4)}</h4>;
      }
      if (line.startsWith('## ')) {
        return <h3 key={i} className="font-bold text-sm mt-2">{line.slice(3)}</h3>;
      }
      return <p key={i} className="text-sm" dangerouslySetInnerHTML={{ __html: processed || '&nbsp;' }} />;
    });
  }

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/20 z-40" onClick={onClose} />

      {/* Panel */}
      <div className="fixed right-0 top-0 h-full w-96 bg-white dark:bg-slate-900 shadow-lg z-50 flex flex-col border-l border-gray-200 dark:border-slate-700">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-200 dark:border-slate-700 bg-blue-50">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center">
              <svg className="w-[18px] h-[18px] text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
            </div>
            <div>
              <div className="text-sm font-bold text-gray-900 dark:text-white">Security Copilot</div>
              <div className="text-[10px] text-gray-500 dark:text-slate-400">AI-powered security assistant</div>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <button
              onClick={() => { setShowHistory(!showHistory); if (!showHistory) fetchHistory(); }}
              className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:bg-slate-800 transition"
              title="Conversation history"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </button>
            <button
              onClick={startNewChat}
              className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:bg-slate-800 transition"
              title="New conversation"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 dark:hover:bg-slate-800 transition"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Add-on not enabled gate */}
        {addonEnabled === false && (
          <div className="flex-1 flex flex-col items-center justify-center px-6 text-center">
            <div className="w-14 h-14 rounded-2xl bg-indigo-100 dark:bg-indigo-900/40 text-indigo-600 dark:text-indigo-400 flex items-center justify-center mb-4">
              <svg className="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h3 className="text-base font-bold text-gray-900 dark:text-white mb-1">AI Copilot Add-On</h3>
            <p className="text-sm text-gray-500 dark:text-slate-400 mb-2">
              The AI Security Copilot is available as a paid add-on ($149/mo) or included with the Enterprise plan.
            </p>
            <p className="text-xs text-gray-400 dark:text-slate-500 mb-4">
              Get AI-powered security analysis, natural language queries, and contextual recommendations using your live AuditGraph data.
            </p>
            <span className="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg opacity-60 cursor-not-allowed">
              Contact Admin to Enable
            </span>
          </div>
        )}

        {/* History sidebar */}
        {addonEnabled !== false && showHistory && (
          <div className="border-b border-gray-200 dark:border-slate-700 bg-gray-50 dark:bg-slate-800/50 max-h-48 overflow-y-auto">
            <div className="p-2 space-y-1">
              {conversations.length === 0 && (
                <div className="text-xs text-gray-400 p-2 text-center">No conversations yet</div>
              )}
              {conversations.map(c => (
                <button
                  key={c.id}
                  onClick={() => {
                    setConversationId(c.id);
                    setShowHistory(false);
                    // Load conversation messages
                    fetch(`/api/copilot/conversations`)
                      .then(r => r.ok ? r.json() : null)
                      .catch(() => null);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-lg text-xs hover:bg-gray-100 dark:hover:bg-slate-700 transition ${
                    conversationId === c.id ? 'bg-indigo-50 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300' : 'text-gray-700 dark:text-slate-300'
                  }`}
                >
                  <div className="font-medium truncate">{c.title}</div>
                  <div className="text-[10px] text-gray-400 mt-0.5">{c.message_count} messages</div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Not configured warning */}
        {addonEnabled !== false && !configured && messages.length === 0 && (
          <div className="mx-4 mt-4 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700 rounded-lg">
            <div className="text-xs font-medium text-amber-800 dark:text-amber-300">API Key Required</div>
            <div className="text-[10px] text-amber-600 dark:text-amber-400 mt-1">
              Configure your Anthropic API key in Settings to use the Security Copilot.
            </div>
          </div>
        )}

        {/* Suggestions */}
        {addonEnabled !== false && messages.length === 0 && suggestions.length > 0 && (
          <div className="px-4 pt-4">
            <div className="text-[10px] font-semibold text-gray-500 dark:text-slate-400 uppercase mb-2">Quick Ask</div>
            <div className="flex flex-wrap gap-1.5">
              {suggestions.map((s, i) => (
                <button
                  key={i}
                  onClick={() => sendMessage(s)}
                  disabled={loading}
                  className="px-2.5 py-1.5 rounded-lg text-[11px] bg-gray-100 dark:bg-slate-800 text-gray-700 dark:text-slate-300 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 hover:text-indigo-700 dark:hover:text-indigo-300 border border-gray-200 dark:border-slate-600 transition"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Messages */}
        {addonEnabled !== false && <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
          {messages.map((msg, i) => (
            <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[85%] rounded-xl px-3 py-2 ${
                msg.role === 'user'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-gray-100 dark:bg-slate-800 text-gray-900 dark:text-slate-100'
              }`}>
                {msg.role === 'user' ? (
                  <p className="text-sm">{msg.content}</p>
                ) : (
                  <div className="space-y-1">{renderMarkdown(msg.content)}</div>
                )}
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start">
              <div className="bg-gray-100 dark:bg-slate-800 rounded-xl px-4 py-3">
                <div className="flex items-center gap-1">
                  <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <div className="w-1.5 h-1.5 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>}

        {/* Input */}
        {addonEnabled !== false && (
          <div className="border-t border-gray-200 dark:border-slate-700 px-4 py-3">
            <div className="flex items-center gap-2">
              <input
                ref={inputRef}
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about your security posture..."
                className="flex-1 px-3 py-2 border border-gray-300 dark:border-slate-600 rounded-lg text-sm bg-white dark:bg-slate-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                disabled={loading}
              />
              <button
                onClick={() => sendMessage()}
                disabled={loading || !input.trim()}
                className={`p-2 rounded-lg transition ${
                  loading || !input.trim()
                    ? 'text-gray-300 dark:text-slate-600 cursor-not-allowed'
                    : 'text-indigo-600 hover:bg-indigo-50 dark:hover:bg-indigo-900/30'
                }`}
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                </svg>
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
