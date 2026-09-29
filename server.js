const express = require("express");
const path = require("path");
const crypto = require("crypto");
const dotenv = require("dotenv");
const Razorpay = require("razorpay");

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
*/

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// Use a separate secret for signed booking/ticket tokens.
// For quick testing, it falls back to Razorpay secret.
const BOOKING_SIGNING_SECRET =
  process.env.BOOKING_SIGNING_SECRET || RAZORPAY_KEY_SECRET;

const TICKETS = {
  stag: {
    name: "Stag entry",
    price: 299,
    people: 1
  },

  couple: {
    name: "Couple entry",
    price: 499,
    people: 2
  },

  group: {
    name: "Group of five",
    price: 1099,
    people: 5
  }
};

const razorpay =
  RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET
    ? new Razorpay({
      key_id: RAZORPAY_KEY_ID,
      key_secret: RAZORPAY_KEY_SECRET
    })
    : null;

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function newReceipt() {
  const time = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();

  return `DR${time}${random}`.slice(0, 40);
}

function createToken(payload) {
  if (!BOOKING_SIGNING_SECRET) {
    throw new Error("BOOKING_SIGNING_SECRET is not configured.");
  }

  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const signature = crypto
    .createHmac("sha256", BOOKING_SIGNING_SECRET)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifyToken(token) {
  if (!BOOKING_SIGNING_SECRET || typeof token !== "string") {
    return null;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return null;
  }

  const [encoded, suppliedSignature] = parts;

  const expectedSignature = crypto
    .createHmac("sha256", BOOKING_SIGNING_SECRET)
    .update(encoded)
    .digest("base64url");

  if (expectedSignature.length !== suppliedSignature.length) {
    return null;
  }

  const valid = crypto.timingSafeEqual(
    Buffer.from(expectedSignature),
    Buffer.from(suppliedSignature)
  );

  if (!valid) {
    return null;
  }

  try {
    return JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8")
    );
  } catch {
    return null;
  }
}

function verifyRazorpaySignature(orderId, paymentId, signature) {
  if (!RAZORPAY_KEY_SECRET || !orderId || !paymentId || !signature) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");

  const supplied = String(signature);

  if (expected.length !== supplied.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(supplied)
  );
}

function verifyWebhookSignature(rawBody, signature) {
  if (!WEBHOOK_SECRET || !signature || !rawBody) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  const supplied = String(signature);

  if (expected.length !== supplied.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(supplied)
  );
}

function normalizeUtr(value) {
  return String(value ?? "").trim();
}

function getProviderReferences(payment) {
  const acquirer = payment?.acquirer_data || {};

  return [
    acquirer.rrn,
    acquirer.bank_transaction_id,
    acquirer.transaction_id,
    acquirer.upi_transaction_id
  ]
    .filter(Boolean)
    .map(value => String(value).trim());
}

function buildTicketId(paymentId) {
  const hash = crypto
    .createHash("sha256")
    .update(paymentId)
    .digest("hex")
    .slice(0, 10)
    .toUpperCase();

  return `DR-${hash}`;
}

function getTicketFromOrder(order, payment, utr) {
  const notes = order.notes || {};

  const type = String(notes.ticket_type || "");
  const ticket = TICKETS[type];

  if (!ticket) {
    throw new Error("Invalid ticket type in Razorpay order.");
  }

  const quantity = Number(notes.quantity);

  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10) {
    throw new Error("Invalid ticket quantity in Razorpay order.");
  }

  const ticketId = buildTicketId(payment.id);

  return {
    ticketId,
    bookingId: notes.booking_id || null,
    name: notes.customer_name || "",
    phone: notes.customer_phone || "",
    email: notes.customer_email || "",
    ticket: ticket.name,
    ticketType: type,
    quantity,
    admits: ticket.people * quantity,
    amount: ticket.price * quantity,
    paymentId: payment.id,
    razorpayOrderId: order.id,
    utr,
    status: "VERIFIED",
    verifiedAt: new Date().toISOString()
  };
}

function publicTicket(ticket) {
  return {
    ticketId: ticket.ticketId,
    bookingId: ticket.bookingId,
    name: ticket.name,
    phone: ticket.phone,
    email: ticket.email,
    ticket: ticket.ticket,
    quantity: ticket.quantity,
    admits: ticket.admits,
    amount: ticket.amount,
    paymentId: ticket.paymentId,
    razorpayOrderId: ticket.razorpayOrderId,
    utr: ticket.utr,
    status: ticket.status,
    verifiedAt: ticket.verifiedAt
  };
}

/*
|--------------------------------------------------------------------------
| WEBHOOK
|
| IMPORTANT:
| This must be BEFORE express.json() so the raw request body is available
| for Razorpay HMAC verification.
|--------------------------------------------------------------------------
*/

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    try {
      const signature = req.headers["x-razorpay-signature"];

      if (!verifyWebhookSignature(req.body, signature)) {
        return res.status(400).send("Invalid webhook signature");
      }

      const event = JSON.parse(req.body.toString("utf8"));

      console.log("Razorpay webhook received:", event.event);

      // We deliberately do not write to the local filesystem here.
      // Later, connect this event to PostgreSQL/Neon for persistent storage.

      return res.status(200).json({
        received: true
      });
    } catch (error) {
      console.error("Webhook error:", error);
      return res.status(400).send("Invalid webhook payload");
    }
  }
);

/*
|--------------------------------------------------------------------------
| Middleware
|--------------------------------------------------------------------------
*/

app.use(express.json({ limit: "100kb" }));

app.use(
  express.static(path.join(__dirname, "public"))
);

/*
|--------------------------------------------------------------------------
| Health
|--------------------------------------------------------------------------
*/

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Dandiya Raas",
    razorpayConfigured: Boolean(razorpay)
  });
});

/*
|--------------------------------------------------------------------------
| Razorpay Config
|--------------------------------------------------------------------------
*/

app.get("/api/config", (req, res) => {
  if (!RAZORPAY_KEY_ID) {
    return res.status(503).json({
      error: "Razorpay Key ID is not configured."
    });
  }

  return res.json({
    keyId: RAZORPAY_KEY_ID
  });
});

/*
|--------------------------------------------------------------------------
| CREATE ORDER
|--------------------------------------------------------------------------
*/

app.post("/api/orders", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({
        error: "Razorpay is not configured on the server."
      });
    }

    const {
      name,
      phone,
      email,
      type,
      qty
    } = req.body || {};

    const ticket = TICKETS[type];
    const quantity = Number(qty);

    if (!ticket) {
      return res.status(400).json({
        error: "Invalid ticket type."
      });
    }

    if (
      !Number.isInteger(quantity) ||
      quantity < 1 ||
      quantity > 10
    ) {
      return res.status(400).json({
        error: "Quantity must be between 1 and 10."
      });
    }

    const customerName = String(name || "").trim();
    const customerPhone = String(phone || "").trim();
    const customerEmail = String(email || "").trim();

    if (customerName.length < 2) {
      return res.status(400).json({
        error: "Enter a valid full name."
      });
    }

    if (!/^[6-9]\d{9}$/.test(customerPhone)) {
      return res.status(400).json({
        error: "Enter a valid 10-digit mobile number."
      });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customerEmail)
    ) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    const amountRupees = ticket.price * quantity;
    const amountPaise = amountRupees * 100;

    const receipt = newReceipt();

    /*
     * Create the order first.
     * Razorpay recommends creating Orders on the server.
     */
    const razorpayOrder = await razorpay.orders.create({
      amount: amountPaise,
      currency: "INR",
      receipt,
      notes: {
        customer_name: customerName,
        customer_phone: customerPhone,
        customer_email: customerEmail,
        ticket_type: type,
        quantity: String(quantity)
      }
    });

    /*
     * Create a signed booking token containing the Razorpay order ID.
     * No local database/file is needed for this stage.
     */
    const bookingId = createToken({
      orderId: razorpayOrder.id,
      createdAt: Date.now()
    });

    /*
     * We cannot update the order's notes after creation in this flow,
     * so bookingId is returned to the frontend and tied cryptographically
     * to the order ID.
     */

    return res.json({
      ok: true,
      bookingId,
      orderId: razorpayOrder.id,
      amount: amountRupees,
      currency: "INR",
      keyId: RAZORPAY_KEY_ID
    });
  } catch (error) {
    console.error("Create order error:", error);

    return res.status(500).json({
      error: "Could not create Razorpay payment order."
    });
  }
});

/*
|--------------------------------------------------------------------------
| VERIFY RAZORPAY PAYMENT
|--------------------------------------------------------------------------
*/

app.post("/api/verify-payment", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({
        error: "Razorpay is not configured."
      });
    }

    const {
      bookingId,
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body || {};

    const booking = verifyToken(bookingId);

    if (!booking) {
      return res.status(400).json({
        error: "Invalid booking token."
      });
    }

    if (booking.orderId !== razorpay_order_id) {
      return res.status(400).json({
        error: "Order mismatch."
      });
    }

    /*
     * Verify Checkout signature on the backend.
     */
    const validSignature = verifyRazorpaySignature(
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    );

    if (!validSignature) {
      return res.status(400).json({
        error: "Payment signature verification failed."
      });
    }

    /*
     * Fetch the order directly from Razorpay.
     */
    const order = await razorpay.orders.fetch(
      razorpay_order_id
    );

    /*
     * Fetch the payment directly from Razorpay.
     */
    const payment = await razorpay.payments.fetch(
      razorpay_payment_id
    );

    if (payment.order_id !== order.id) {
      return res.status(400).json({
        error: "Payment does not belong to this order."
      });
    }

    if (
      payment.amount !== order.amount ||
      payment.currency !== "INR"
    ) {
      return res.status(400).json({
        error: "Payment amount does not match the order."
      });
    }

    if (payment.status !== "captured") {
      return res.status(400).json({
        error: `Payment status is ${payment.status}.`
      });
    }

    return res.json({
      ok: true,
      bookingId,
      orderId: order.id,
      paymentId: payment.id,
      status: "PAYMENT_VERIFIED",
      method: payment.method
    });
  } catch (error) {
    console.error("Payment verification error:", error);

    return res.status(500).json({
      error: "Could not verify the Razorpay payment."
    });
  }
});

/*
|--------------------------------------------------------------------------
| VERIFY UTR / RRN
|--------------------------------------------------------------------------
|
| This is NOT accepted as proof by itself.
| The server independently fetches the Razorpay payment and compares
| the entered UTR against Razorpay's UPI/acquirer references.
|--------------------------------------------------------------------------
*/

app.post("/api/verify-utr", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({
        error: "Razorpay is not configured."
      });
    }

    const {
      bookingId,
      paymentId,
      utr
    } = req.body || {};

    const booking = verifyToken(bookingId);

    if (!booking) {
      return res.status(400).json({
        error: "Invalid booking token."
      });
    }

    const normalizedUtr = normalizeUtr(utr);

    if (!/^\d{8,20}$/.test(normalizedUtr)) {
      return res.status(400).json({
        error: "Enter a valid UTR/reference number."
      });
    }

    if (!paymentId) {
      return res.status(400).json({
        error: "Payment ID is required."
      });
    }

    /*
     * Fetch the original Razorpay order.
     */
    const order = await razorpay.orders.fetch(
      booking.orderId
    );

    if (order.id !== booking.orderId) {
      return res.status(400).json({
        error: "Booking/order mismatch."
      });
    }

    /*
     * Fetch actual payment from Razorpay.
     */
    const payment = await razorpay.payments.fetch(
      paymentId
    );

    if (payment.order_id !== order.id) {
      return res.status(400).json({
        error: "Payment does not belong to this booking."
      });
    }

    if (payment.status !== "captured") {
      return res.status(400).json({
        error: "Payment has not been captured."
      });
    }

    if (
      payment.amount !== order.amount ||
      payment.currency !== "INR"
    ) {
      return res.status(400).json({
        error: "Payment amount does not match the order."
      });
    }

    /*
     * UTR/RRN verification only makes sense for UPI.
     */
    if (payment.method !== "upi") {
      return res.status(400).json({
        error: "This payment was not made through UPI."
      });
    }

    /*
     * Compare user's UTR with actual Razorpay provider references.
     */
    const providerReferences =
      getProviderReferences(payment);

    const utrMatches = providerReferences.some(
      reference => reference === normalizedUtr
    );

    if (!utrMatches) {
      return res.status(400).json({
        error:
          "UTR does not match the verified Razorpay UPI transaction. No ticket was issued."
      });
    }

    /*
     * UTR is valid.
     * ONLY NOW create the ticket.
     */
    const ticket = getTicketFromOrder(
      order,
      payment,
      normalizedUtr
    );

    /*
     * Sign the ticket data so the browser cannot modify it.
     */
    const ticketToken = createToken({
      ticket,
      issuedAt: Date.now()
    });

    return res.json({
      ok: true,
      message:
        "Payment and UTR verified. Ticket is now available.",
      ticket: publicTicket(ticket),
      ticketToken
    });
  } catch (error) {
    console.error("UTR verification error:", error);

    return res.status(500).json({
      error:
        "UTR verification service failed. Please try again."
    });
  }
});

/*
|--------------------------------------------------------------------------
| VERIFY / RETRIEVE TICKET
|--------------------------------------------------------------------------
|
| The ticket token is signed by the server.
| Razorpay is checked again before returning the ticket.
|--------------------------------------------------------------------------
*/

app.get("/api/ticket/:ticketToken", async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({
        error: "Razorpay is not configured."
      });
    }

    const token = req.params.ticketToken;

    const payload = verifyToken(token);

    if (!payload?.ticket) {
      return res.status(404).json({
        error: "Invalid or expired ticket."
      });
    }

    const ticket = payload.ticket;

    const order = await razorpay.orders.fetch(
      ticket.razorpayOrderId
    );

    const payment = await razorpay.payments.fetch(
      ticket.paymentId
    );

    if (
      payment.order_id !== order.id ||
      payment.status !== "captured" ||
      payment.method !== "upi" ||
      payment.amount !== order.amount ||
      payment.currency !== "INR"
    ) {
      return res.status(400).json({
        error: "Ticket payment could not be revalidated."
      });
    }

    const providerReferences =
      getProviderReferences(payment);

    if (!providerReferences.includes(ticket.utr)) {
      return res.status(400).json({
        error: "Ticket UTR is no longer valid."
      });
    }

    return res.json({
      ok: true,
      ticket: publicTicket(ticket)
    });
  } catch (error) {
    console.error("Ticket retrieval error:", error);

    return res.status(500).json({
      error: "Could not validate the ticket."
    });
  }
});

/*
|--------------------------------------------------------------------------
| Frontend
|--------------------------------------------------------------------------
*/

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/*
|--------------------------------------------------------------------------
| Local + Vercel
|--------------------------------------------------------------------------
|
| Vercel can deploy Express apps directly.
| Local development still uses `npm start`.
|--------------------------------------------------------------------------
*/

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(
      `Dandiya Raas running at http://localhost:${PORT}`
    );
  });
}

module.exports = app;