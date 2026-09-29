# Dandiya Raas 2026 — Razorpay + UTR verified tickets

This version keeps the existing Dandiya Raas landing page and replaces the manual UPI/WhatsApp trust model with:

1. Customer selects a ticket.
2. Server creates a Razorpay Order.
3. Razorpay Checkout opens.
4. Server verifies the Razorpay checkout signature and fetches the payment.
5. Customer enters the UPI UTR/RRN.
6. Server fetches the real Razorpay payment and compares the entered UTR against `acquirer_data` reference fields.
7. Only a matching captured UPI payment gets `ticketIssued=true` and a ticket download/print option.
8. The booking is persisted in `data/bookings.json` for this starter implementation.

## Setup

Requirements: Node.js 18+.

```bash
npm install
copy .env.example .env
```

Edit `.env`:

```text
RAZORPAY_KEY_ID=rzp_test_your_key_id
RAZORPAY_KEY_SECRET=your_test_secret
WEBHOOK_SECRET=choose_a_random_webhook_secret
PORT=3000
BASE_URL=http://localhost:3000
```

Start:

```bash
npm start
```

Open `http://localhost:3000`.

## Razorpay dashboard

Use Test Mode first. Configure a webhook to:

`https://YOUR-DOMAIN/api/webhook`

Use the same `WEBHOOK_SECRET` value in the Razorpay dashboard and `.env`. Add the payment-captured event(s) you need for your account.

For production, use HTTPS and Live Mode keys. Never put the Razorpay secret in frontend JavaScript or commit `.env` to Git.

## Important UTR behavior

The backend does **not** accept a syntactically valid number as proof of payment. It checks:

- booking/order match
- Razorpay checkout signature
- captured payment status
- exact amount
- INR currency
- UPI payment method
- UTR/RRN against the payment's Razorpay acquirer reference data
- duplicate UTR protection

If any check fails, no ticket is issued.

## Production upgrade recommended

`data/bookings.json` is intentionally simple for development/demo use. For a real event, move bookings to PostgreSQL/MySQL and add an authenticated admin dashboard plus QR entry validation. Also configure HTTPS, rate limiting, backups, webhook monitoring and proper secret storage.
"# Dandiyaa" 
