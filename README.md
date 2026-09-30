# Ticketfy v4

Modern event ticketing website prototype.

## Run locally
1. Install Node.js.
2. Open a terminal in this folder.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000` in your browser.

## Included
- Event discovery and search
- Event details and ticket selection
- M-Pesa STK Push backend configuration
- Ticketfy accounts: sign up, sign in and sign out
- Help & Support center
- About Ticketfy page
- Three-dot mobile menu
- QR ticket generation after confirmed payment

Accounts are stored locally in `data/users.json` on the server and passwords are stored as scrypt hashes. For production, use a persistent database and secure session store.
