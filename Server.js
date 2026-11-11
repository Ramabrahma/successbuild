/**
 * Gmail Mailbox Hub backend
 *
 * Required environment variables:
 * GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
 * GOOGLE_REDIRECT_URI=http://localhost:3001/auth/google/callback
 * APP_ADMIN_PASSWORD=<strong password>
 * SESSION_SECRET=<at least 32 random characters>
 * STORE_ENCRYPTION_KEY=<64 hex characters; generate with: openssl rand -hex 32>
 * CLIENT_ORIGIN=http://localhost:5174
 * PORT=3001
 *
 * Google Cloud setup:
 * 1. Enable Gmail API and configure an OAuth consent screen.
 * 2. Create a Web Application OAuth client.
 * 3. Add GOOGLE_REDIRECT_URI as an authorized redirect URI.
 * 4. While the consent screen is in Testing, add every mailbox owner as a test user.
 *
 * Install/run: npm install && npm run dev
 * Production: npm run build, then start with NODE_ENV=production
 */
import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import cors from 'cors';
import { google } from 'googleapis';

const app = express();
const PORT = Number(process.env.PORT || 3001);
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5174';
const STORE_FILE = path.resolve('.gmail-accounts.enc');
const required = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI', 'APP_ADMIN_PASSWORD', 'SESSION_SECRET', 'STORE_ENCRYPTION_KEY'];
for (const key of required) if (!process.env[key]) throw new Error(`Missing environment variable: ${key}`);
if (!/^[a-f\d]{64}$/i.test(process.env.STORE_ENCRYPTION_KEY)) throw new Error('STORE_ENCRYPTION_KEY must be 64 hexadecimal characters.');

if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 'loopback');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: CLIENT_ORIGIN,
  credentials: true
}));
app.use(express.json({ limit: '32kb' }));
app.use(session({
  name: 'mailhub.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));

const key = Buffer.from(process.env.STORE_ENCRYPTION_KEY, 'hex');
const encrypt = (value) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return JSON.stringify({ iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), body: body.toString('base64') });
};
const decrypt = (raw) => {
  const payload = JSON.parse(raw);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(payload.body, 'base64')), decipher.final()]).toString('utf8'));
};
const loadAccounts = () => fs.existsSync(STORE_FILE) ? decrypt(fs.readFileSync(STORE_FILE, 'utf8')) : {};
const saveAccounts = (accounts) => fs.writeFileSync(STORE_FILE, encrypt(accounts), { mode: 0o600 });
const safeEqual = (a, b) => {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
};
const requireAdmin = (req, res, next) => req.session.admin ? next() : res.status(401).json({ error: 'Sign in required.' });
const oauthClient = () => new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_REDIRECT_URI);
const gmailFor = (email) => {
  const account = loadAccounts()[email];
  if (!account?.tokens) throw Object.assign(new Error('Mailbox is not connected.'), { status: 404 });
  const auth = oauthClient();
  auth.setCredentials(account.tokens);
  auth.on('tokens', (newTokens) => {
    const accounts = loadAccounts();
    if (accounts[email]) {
      accounts[email].tokens = { ...accounts[email].tokens, ...newTokens };
      saveAccounts(accounts);
    }
  });
  return google.gmail({ version: 'v1', auth });
};
const header = (message, name) => message.payload?.headers?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value || '';
const route = (handler) => async (req, res) => {
  try {
    await handler(req, res);
  } catch (error) {
    if (error.response?.data?.error === 'invalid_grant') {
      return res.status(409).json({ error: 'Google authorization expired or was revoked. Connect this mailbox again.' });
    }
    const status = Number(error.response?.status || error.status || error.code);
    res.status(status >= 400 && status <= 599 ? status : 500)
      .json({ error: error.message || 'Request failed.' });
  }
};

app.post('/api/login', (req, res) => {
  if (!safeEqual(req.body?.password || '', process.env.APP_ADMIN_PASSWORD)) return res.status(401).json({ error: 'Incorrect app password.' });
  req.session.regenerate((error) => {
    if (error) return res.status(500).json({ error: 'Unable to create a session.' });
    req.session.admin = true;
    res.json({ ok: true });
  });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/session', (req, res) => res.json({ authenticated: Boolean(req.session.admin) }));

app.get('/auth/google', requireAdmin, (req, res) => {
  const state = crypto.randomBytes(24).toString('hex');
  req.session.oauthState = state;
  const url = oauthClient().generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent select_account',
    include_granted_scopes: true,
    state,
    scope: ['openid', 'email', 'https://mail.google.com/']
  });
  res.redirect(url);
});
app.get('/auth/google/callback', route(async (req, res) => {
  if (!req.session.admin || !req.query.state || !safeEqual(req.query.state, req.session.oauthState || '')) return res.status(403).send('Invalid OAuth state.');
  delete req.session.oauthState;
  if (req.query.error || typeof req.query.code !== 'string' || !req.query.code) {
    return res.redirect(`${CLIENT_ORIGIN}/?oauth=cancelled`);
  }
  const auth = oauthClient();
  const { tokens } = await auth.getToken(String(req.query.code || ''));
  auth.setCredentials(tokens);
  const oauth2 = google.oauth2({ version: 'v2', auth });
  const { data } = await oauth2.userinfo.get();
  if (!data.email) throw new Error('Google did not return an email address.');
  const accounts = loadAccounts();
  accounts[data.email] = { email: data.email, name: data.name || data.email, picture: data.picture || '', tokens: { ...accounts[data.email]?.tokens, ...tokens } };
  saveAccounts(accounts);
  res.redirect(`${CLIENT_ORIGIN}/?connected=1`);
}));

app.get('/api/accounts', requireAdmin, (req, res) => {
  const accounts = Object.values(loadAccounts()).map(({ tokens, ...publicData }) => publicData);
  res.json(accounts);
});
app.delete('/api/accounts/:email', requireAdmin, (req, res) => {
  const accounts = loadAccounts();
  delete accounts[req.params.email];
  saveAccounts(accounts);
  res.json({ ok: true });
});
app.get('/api/accounts/:email/messages', requireAdmin, route(async (req, res) => {
  const email = req.params.email;
  const gmail = gmailFor(email);
  const maxResults = Math.max(1, Math.min(Math.trunc(Number(req.query.limit)) || 30, 100));
  const list = await gmail.users.messages.list({
    userId: 'me',
    maxResults,
    q: String(req.query.q || ''),
    pageToken: typeof req.query.pageToken === 'string' ? req.query.pageToken : undefined,
    includeSpamTrash: true
  });
  const messages = await Promise.all((list.data.messages || []).map(async ({ id }) => {
    const { data } = await gmail.users.messages.get({ userId: 'me', id, format: 'metadata', metadataHeaders: ['From', 'To', 'Subject', 'Date'] });
    return { id: data.id, threadId: data.threadId, from: header(data, 'From'), to: header(data, 'To'), subject: header(data, 'Subject') || '(No subject)', date: header(data, 'Date'), snippet: data.snippet || '', labels: data.labelIds || [] };
  }));
  res.json({ messages, nextPageToken: list.data.nextPageToken || null, resultSizeEstimate: list.data.resultSizeEstimate || 0 });
}));
app.get('/api/accounts/:email/messages/:messageId', requireAdmin, route(async (req, res) => {
  const gmail = gmailFor(req.params.email);
  const { data } = await gmail.users.messages.get({ userId: 'me', id: req.params.messageId, format: 'full' });
  const parts = [data.payload].filter(Boolean);
  for (let index = 0; index < parts.length; index++) {
    parts.push(...(parts[index].parts || []));
  }
  const candidates = parts.filter((part) => !part.filename && part.body?.size);
  const bodyPart = candidates.find((part) => part.mimeType === 'text/plain')
    || candidates.find((part) => part.mimeType === 'text/html');
  let encodedBody = bodyPart?.body?.data;
  if (!encodedBody && bodyPart?.body?.attachmentId) {
    const attachment = await gmail.users.messages.attachments.get({
      userId: 'me', messageId: data.id, id: bodyPart.body.attachmentId
    });
    encodedBody = attachment.data.data;
  }
  res.json({
    subject: header(data, 'Subject') || '(No subject)',
    from: header(data, 'From'),
    to: header(data, 'To'),
    date: header(data, 'Date'),
    body: encodedBody ? Buffer.from(encodedBody, 'base64url').toString('utf8') : data.snippet || '',
    mimeType: encodedBody ? bodyPart.mimeType : 'text/plain',
    attachments: parts.filter((part) => part.filename).map((part) => part.filename)
  });
}));
app.delete('/api/accounts/:email/messages/:messageId', requireAdmin, route(async (req, res) => {
  if (req.body?.confirmation !== 'PERMANENTLY DELETE') return res.status(400).json({ error: 'Exact deletion confirmation is required.' });
  const gmail = gmailFor(req.params.email);
  await gmail.users.messages.delete({ userId: 'me', id: req.params.messageId });
  res.json({ ok: true });
}));

app.use(['/api', '/auth'], (_req, res) => res.status(404).json({ error: 'Endpoint not found.' }));

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.resolve('dist')));
  app.use((_req, res) => res.sendFile(path.resolve('dist/index.html')));
}
app.listen(PORT, process.env.HOST || '127.0.0.1', () => console.log(`Mailbox Hub API running on port ${PORT}`));
