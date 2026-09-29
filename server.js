const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const dotenv = require('dotenv');
const Razorpay = require('razorpay');

dotenv.config();
const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_FILE = path.join(__dirname, 'data', 'bookings.json');
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]');

const TICKETS = {
  stag: { name: 'Stag entry', price: 299, people: 1 },
  couple: { name: 'Couple entry', price: 499, people: 2 },
  group: { name: 'Group of five', price: 1099, people: 5 }
};

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || '',
  key_secret: process.env.RAZORPAY_KEY_SECRET || ''
});

function readBookings() { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function writeBookings(rows) { fs.writeFileSync(DB_FILE, JSON.stringify(rows, null, 2)); }
function newBookingId() {
  const stamp = new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
  return `DR-${stamp}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}
function publicBooking(b) {
  return {
    bookingId: b.bookingId,
    name: b.name,
    phone: b.phone,
    email: b.email,
    ticket: b.ticket,
    quantity: b.quantity,
    admits: b.admits,
    amount: b.amount,
    paymentId: b.paymentId,
    utr: b.utr,
    status: b.status,
    createdAt: b.createdAt
  };
}

app.use(express.json({ limit: '100kb', verify: (req, res, buf) => { if (req.originalUrl === '/api/webhook') req.rawBody = Buffer.from(buf); } }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (req, res) => {
  if (!process.env.RAZORPAY_KEY_ID) return res.status(503).json({ error: 'Razorpay is not configured on the server.' });
  res.json({ keyId: process.env.RAZORPAY_KEY_ID });
});

app.post('/api/orders', async (req, res) => {
  try {
    const { name, phone, email, type, qty } = req.body || {};
    const t = TICKETS[type];
    const q = Number(qty);
    if (!t || !Number.isInteger(q) || q < 1 || q > 10) return res.status(400).json({ error: 'Invalid ticket selection.' });
    if (typeof name !== 'string' || name.trim().length < 2) return res.status(400).json({ error: 'Invalid name.' });
    if (!/^[6-9]\d{9}$/.test(String(phone))) return res.status(400).json({ error: 'Invalid mobile number.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email))) return res.status(400).json({ error: 'Invalid email.' });
    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) return res.status(503).json({ error: 'Razorpay keys are not configured.' });

    const amount = t.price * q * 100;
    const bookingId = newBookingId();
    const order = await razorpay.orders.create({
      amount,
      currency: 'INR',
      receipt: bookingId,
      notes: { booking_id: bookingId, ticket_type: type, quantity: String(q) }
    });

    const rows = readBookings();
    rows.push({ bookingId, name: name.trim(), phone: String(phone), email: String(email).trim(), type, ticket: t.name, quantity: q, admits: t.people * q, amount: t.price * q, razorpayOrderId: order.id, paymentId: null, signatureVerified: false, utr: null, status: 'ORDER_CREATED', ticketIssued: false, createdAt: new Date().toISOString() });
    writeBookings(rows);
    res.json({ orderId: order.id, amount: t.price * q, currency: 'INR', bookingId, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not create payment order.' });
  }
});

app.post('/api/verify-payment', async (req, res) => {
  try {
    const { bookingId, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
    const rows = readBookings();
    const b = rows.find(x => x.bookingId === bookingId);
    if (!b) return res.status(404).json({ error: 'Booking not found.' });
    if (b.razorpayOrderId !== razorpay_order_id) return res.status(400).json({ error: 'Order mismatch.' });

    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${b.razorpayOrderId}|${razorpay_payment_id}`).digest('hex');
    if (expected.length !== String(razorpay_signature).length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(razorpay_signature)))) return res.status(400).json({ error: 'Payment signature verification failed.' });

    const payment = await razorpay.payments.fetch(razorpay_payment_id);
    if (payment.order_id !== b.razorpayOrderId || payment.amount !== b.amount * 100 || payment.currency !== 'INR') return res.status(400).json({ error: 'Payment does not match this booking.' });
    if (payment.status !== 'captured') return res.status(400).json({ error: `Payment status is ${payment.status}. Ticket cannot be issued yet.` });

    b.paymentId = razorpay_payment_id;
    b.signatureVerified = true;
    b.status = 'PAYMENT_VERIFIED';
    writeBookings(rows);
    res.json({ ok: true, paymentId: b.paymentId, status: b.status, method: payment.method });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not verify the Razorpay payment.' });
  }
});

app.post('/api/verify-utr', async (req, res) => {
  try {
    const { bookingId, utr } = req.body || {};
    if (!/^\d{8,20}$/.test(String(utr || ''))) return res.status(400).json({ error: 'Enter a valid UTR/reference number.' });
    const rows = readBookings();
    const b = rows.find(x => x.bookingId === bookingId);
    if (!b) return res.status(404).json({ error: 'Booking not found.' });
    if (!b.signatureVerified || !b.paymentId || b.status !== 'PAYMENT_VERIFIED') return res.status(400).json({ error: 'The Razorpay payment has not been verified yet.' });
    if (b.ticketIssued) return res.status(409).json({ error: 'A ticket has already been issued for this booking.', ticket: publicBooking(b) });

    const duplicate = rows.find(x => x.utr === String(utr) && x.bookingId !== bookingId && x.ticketIssued);
    if (duplicate) return res.status(409).json({ error: 'This UTR has already been used for another ticket.' });

    const payment = await razorpay.payments.fetch(b.paymentId);
    if (payment.status !== 'captured' || payment.amount !== b.amount * 100 || payment.order_id !== b.razorpayOrderId) return res.status(400).json({ error: 'Payment could not be confirmed.' });
    if (payment.method !== 'upi') return res.status(400).json({ error: 'This booking was not paid using UPI. A UTR can only be checked for a UPI payment.' });

    const acq = payment.acquirer_data || {};
    const providerRefs = [acq.rrn, acq.bank_transaction_id, acq.transaction_id, acq.upi_transaction_id].filter(Boolean).map(String);
    const normalized = String(utr).trim();
    if (!providerRefs.includes(normalized)) return res.status(400).json({ error: 'UTR does not match the verified Razorpay UPI transaction. No ticket was issued.' });

    b.utr = normalized;
    b.status = 'VERIFIED';
    b.ticketIssued = true;
    writeBookings(rows);
    res.json({ ok: true, ticket: publicBooking(b), message: 'UTR verified. Ticket is now available.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'UTR verification service failed. Please try again.' });
  }
});

app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    if (!process.env.WEBHOOK_SECRET || !signature) return res.status(400).send('Webhook secret/signature missing');
    const expected = crypto.createHmac('sha256', process.env.WEBHOOK_SECRET).update(req.rawBody || Buffer.from('')).digest('hex');
    if (expected.length !== String(signature).length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(signature)))) return res.status(400).send('Invalid signature');
    const event = JSON.parse(req.body.toString('utf8'));
    const payment = event.payload?.payment?.entity;
    if (payment?.order_id && payment.status === 'captured') {
      const rows = readBookings();
      const b = rows.find(x => x.razorpayOrderId === payment.order_id);
      if (b && !b.paymentId) { b.paymentId = payment.id; b.status = 'PAYMENT_WEBHOOK_CAPTURED'; writeBookings(rows); }
    }
    res.json({ received: true });
  } catch (e) { console.error(e); res.status(400).send('Invalid webhook'); }
});

app.get('/api/ticket/:bookingId', (req, res) => {
  const b = readBookings().find(x => x.bookingId === req.params.bookingId);
  if (!b || !b.ticketIssued) return res.status(404).json({ error: 'Ticket not available.' });
  res.json(publicBooking(b));
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Dandiya Raas server running at http://localhost:${PORT}`));
