# Node 2602 Exam on Authentication

Full authentication: registration, login, JWT access + rotating refresh tokens,
email verification, password reset, role-based authorization, account lockout.

## Run it

```bash
npm install
# make sure MongoDB is running:  brew services start mongodb-community
npm run dev          # or: npm start
```

Open <http://localhost:5000> for a small test page, or use the endpoints below.

```bash
node smoke-test.js   # walks the whole flow against a throwaway test database
```

## Endpoints

| Method | Route | Access | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | public | Create an account, receive tokens |
| POST | `/api/auth/login` | public | Log in |
| POST | `/api/auth/refresh` | cookie | Exchange refresh token for a new access token |
| POST | `/api/auth/logout` | cookie | End this session |
| POST | `/api/auth/logout-all` | token | End every session |
| GET | `/api/auth/me` | token | Current user |
| GET | `/api/auth/verify-email/:token` | public | Confirm email address |
| POST | `/api/auth/forgot-password` | public | Request a reset link |
| PATCH | `/api/auth/reset-password/:token` | public | Set a new password |
| PATCH | `/api/auth/change-password` | token | Change password while logged in |
| GET | `/api/users/profile` | token | Own profile |
| GET | `/api/users` | admin | List users, paginated |
| DELETE | `/api/users/:id` | admin | Delete a user |

## How the security works — the viva answers

**Passwords are never stored.** A `pre('save')` hook on the User model runs
`bcrypt.hash` with 10 salt rounds whenever the password field changes. bcrypt
salts each hash automatically, so two users with the same password get
different hashes, and it is deliberately slow, which is what makes brute force
expensive. The field is `select: false`, so it is not even loaded unless a
query asks for it, and `toJSON` strips it again on the way out.

**Two tokens, two jobs.** The access token is short-lived (15 min) and is sent
in the `Authorization: Bearer` header — if it leaks, it expires quickly. The
refresh token lasts 7 days and is stored in an `httpOnly`, `sameSite: strict`
cookie, so JavaScript on the page cannot read it and it is not sent
cross-site. That combination limits both XSS and CSRF exposure.

**Refresh tokens are rotated and revocable.** JWTs are stateless and cannot
normally be cancelled, so the SHA-256 hash of each refresh token is stored on
the user document. Every refresh issues a new token and deletes the old hash.
If a token that is validly signed but no longer on file is presented, that
means someone replayed a stolen one — the API then clears every session for
that user and forces a fresh login.

**A password change invalidates old tokens.** `passwordChangedAt` is compared
against the JWT's `iat` claim in the `protect` middleware, so tokens minted
before the change stop working even though they have not expired.

**Brute force is limited twice.** `express-rate-limit` caps the auth routes at
10 requests per 15 minutes per IP, and the account itself locks for 15 minutes
after 5 failed logins.

**No account enumeration.** A wrong password and an unknown email return the
identical 401 message, and `forgot-password` always returns the same success
response, so the API cannot be used to discover who has an account.

**One-time tokens are hashed too.** Verification and reset tokens are random
32-byte values; only their SHA-256 hash is stored, with an expiry. A database
leak therefore does not hand over working reset links.

## Structure

```
src/
  config/      env validation, database connection
  models/      User schema, hashing hook, instance methods
  middleware/  protect, authorize, validate, rate limiters, error handler
  utils/       ApiError, asyncHandler, token signing and cookies
  validators/  express-validator rule sets
  controllers/ authController — the flow logic
  routes/      authRoutes, userRoutes
  app.js       middleware pipeline
  server.js    startup and shutdown
```

## Making yourself an admin

```bash
mongosh auth_demo --eval 'db.users.updateOne({email:"test@example.com"},{$set:{role:"admin"}})'
```
