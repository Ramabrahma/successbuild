import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

const apiOrigin = (import.meta.env.VITE_API_ORIGIN ||
  (import.meta.env.DEV ? 'http://localhost:3001' : '')).replace(/\/$/, '');

async function request(path, options) {
  const response = await fetch(apiOrigin + path, {
    credentials: 'include',
    ...options,
    headers: options?.body ? { 'Content-Type': 'application/json' } : undefined,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
  return data;
}

function App() {
  const [authenticated, setAuthenticated] = useState(null);
  const [password, setPassword] = useState('');
  const [accounts, setAccounts] = useState([]);
  const [email, setEmail] = useState('');
  const [search, setSearch] = useState('');
  const [activeQuery, setActiveQuery] = useState('');
  const [messages, setMessages] = useState([]);
  const [nextPageToken, setNextPageToken] = useState(null);
  const [message, setMessage] = useState(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState(() => {
    const query = new URLSearchParams(window.location.search);
    if (query.has('connected')) return 'Mailbox connected.';
    if (query.get('oauth') === 'cancelled') return 'Google connection was cancelled.';
    return '';
  });

  async function run(action) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
    } catch (failure) {
      setError(failure.message);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    async function initialize() {
      try {
        const session = await request('/api/session');
        setAuthenticated(session.authenticated);
        if (session.authenticated) setAccounts(await request('/api/accounts'));
      } catch (failure) {
        setAuthenticated(false);
        setError(failure.message);
      } finally {
        setBusy(false);
      }
    }
    initialize();
    if (window.location.search) history.replaceState(null, '', window.location.pathname);
  }, []);

  async function signIn(event) {
    event.preventDefault();
    await run(async () => {
      await request('/api/login', { method: 'POST', body: JSON.stringify({ password }) });
      setPassword('');
      setAuthenticated(true);
      setAccounts(await request('/api/accounts'));
    });
  }

  function clearMailbox() {
    setEmail('');
    setSearch('');
    setActiveQuery('');
    setMessages([]);
    setNextPageToken(null);
    setMessage(null);
  }

  async function loadMessages(address, query, token) {
    const params = new URLSearchParams({ q: query });
    if (token) params.set('pageToken', token);
    const result = await request(`/api/accounts/${encodeURIComponent(address)}/messages?${params}`);
    setEmail(address);
    setActiveQuery(query);
    setMessages(previous => token
      ? [...previous, ...result.messages.filter(item => !previous.some(existing => existing.id === item.id))]
      : result.messages);
    setNextPageToken(result.nextPageToken);
    setMessage(null);
  }

  const mailboxPath = `/api/accounts/${encodeURIComponent(email)}`;
  const messagePath = id => `${mailboxPath}/messages/${encodeURIComponent(id)}`;

  return (
    <main style={{ maxWidth: 920, margin: '32px auto', padding: '0 16px', font: '16px system-ui, sans-serif' }}>
      <h1>Gmail Mailbox Hub</h1>
      {error && <p role="alert">{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {busy && <p role="status">Loading…</p>}
      {authenticated === false && (
        <form onSubmit={signIn}>
          <label>Admin password <input type="password" autoComplete="current-password" value={password}
            onChange={event => setPassword(event.target.value)} required /></label>{' '}
          <button disabled={busy}>Sign in</button>
        </form>
      )}
      {authenticated && <>
        <button disabled={busy} onClick={() => window.location.assign(apiOrigin + '/auth/google')}>Connect Gmail</button>{' '}
        <button disabled={busy} onClick={() => run(async () => {
          await request('/api/logout', { method: 'POST' });
          clearMailbox();
          setAccounts([]);
          setAuthenticated(false);
        })}>Sign out</button>
        <h2>Connected mailboxes</h2>
        {accounts.length === 0 && <p>Connect a Gmail account to view messages.</p>}
        <ul>{accounts.map(account => <li key={account.email}>
          <button disabled={busy} onClick={() => run(async () => {
            clearMailbox();
            await loadMessages(account.email, '');
          })}>{account.email}</button>
        </li>)}</ul>
        {email && <section>
          <h2>{email}</h2>
          <form onSubmit={event => {
            event.preventDefault();
            run(() => loadMessages(email, search));
          }}>
            <label>Search Gmail <input type="search" value={search} onChange={event => setSearch(event.target.value)} /></label>{' '}
            <button disabled={busy}>Search</button>{' '}
            <button type="button" disabled={busy} onClick={() => run(() => loadMessages(email, activeQuery))}>Refresh</button>{' '}
            <button type="button" disabled={busy} onClick={() => {
              if (!window.confirm(`Disconnect ${email} from this app?`)) return;
              run(async () => {
                await request(mailboxPath, { method: 'DELETE' });
                setAccounts(previous => previous.filter(account => account.email !== email));
                clearMailbox();
              });
            }}>Disconnect</button>
          </form>
          {messages.length === 0 && !busy && <p>No messages found.</p>}
          <ul>{messages.map(item => <li key={item.id}>
            <button disabled={busy} onClick={() => run(async () => {
              setMessage({ id: item.id, ...await request(messagePath(item.id)) });
            })}>{item.subject}</button>
            <p>{item.from} · {item.date}</p>
          </li>)}</ul>
          {nextPageToken && <button disabled={busy} onClick={() => run(() => loadMessages(email, activeQuery, nextPageToken))}>Load more</button>}
          {message && <article aria-label="Message details">
            <h3>{message.subject}</h3>
            <p>From {message.from}<br />To {message.to}<br />{message.date}</p>
            {message.mimeType === 'text/html' ? (
              <iframe title="Email body" sandbox="" style={{ width: '100%', minHeight: 320 }}
                srcDoc={`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'">${message.body}`} />
            ) : <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{message.body}</pre>}
            {!!message.attachments?.length && <p>Attachments: {message.attachments.join(', ')}</p>}
            <button disabled={busy} onClick={() => setMessage(null)}>Close message</button>{' '}
            <button disabled={busy} onClick={() => {
              const confirmation = window.prompt('Type PERMANENTLY DELETE to remove this message from Gmail.');
              if (confirmation !== 'PERMANENTLY DELETE') return;
              run(async () => {
                await request(messagePath(message.id), { method: 'DELETE', body: JSON.stringify({ confirmation }) });
                setMessages(previous => previous.filter(item => item.id !== message.id));
                setMessage(null);
                setNotice('Message permanently deleted.');
              });
            }}>Permanently delete</button>
          </article>}
        </section>}
      </>}
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
