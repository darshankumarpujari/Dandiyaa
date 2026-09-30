const express = require("express");
const path = require("path");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 3000;

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!RAZORPAY_KEY_ID) {
  console.warn("Missing RAZORPAY_KEY_ID");
}

if (!RAZORPAY_KEY_SECRET) {
  console.warn("Missing RAZORPAY_KEY_SECRET");
}

if (!WEBHOOK_SECRET) {
  console.warn("Missing WEBHOOK_SECRET");
}

if (!DATABASE_URL) {
  console.warn("Missing DATABASE_URL");
}

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  max: 5,
});

/* =========================================================
   RAZORPAY
========================================================= */

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

/* =========================================================
   TICKETS
========================================================= */

const TICKETS = {
  stag: {
    name: "Stag Entry",
    count: 1,
    amount: 29900,
  },

  couple: {
    name: "Couple Entry",
    count: 2,
    amount: 49900,
  },

  group: {
    name: "Group of Five",
    count: 5,
    amount: 109900,
  },
};

/* =========================================================
   HELPERS
========================================================= */

function generateBookingId() {
  const random = crypto
    .randomBytes(4)
    .toString("hex")
    .toUpperCase();

  return `DR26-${random}`;
}

function safeCompare(a, b) {
  if (!a || !b) return false;

  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  if (aa.length !== bb.length) return false;

  return crypto.timingSafeEqual(aa, bb);
}

function verifyPaymentSignature(orderId, paymentId, signature) {
  const expected = crypto
    .createHmac("sha256", RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");

  return safeCompare(expected, signature);
}

function verifyWebhookSignature(rawBody, signature) {
  const expected = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  return safeCompare(expected, signature);
}

/* =========================================================
   WEBHOOK
   IMPORTANT:
   This must come BEFORE express.json()
========================================================= */

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature = req.headers["x-razorpay-signature"];

      if (!signature) {
        return res.status(400).json({
          success: false,
          message: "Missing webhook signature",
        });
      }

      if (!verifyWebhookSignature(req.body, signature)) {
        return res.status(400).json({
          success: false,
          message: "Invalid webhook signature",
        });
      }

      const payload = JSON.parse(req.body.toString("utf8"));

      const eventType = payload.event || "unknown";

      const eventId =
        req.headers["x-razorpay-event-id"] ||
        crypto.randomUUID();

      /* ---------------------------------------------
         Duplicate webhook protection
      --------------------------------------------- */

      const existing = await pool.query(
        `SELECT id
                 FROM webhook_events
                 WHERE event_id = $1`,
        [eventId]
      );

      if (existing.rows.length > 0) {
        return res.status(200).json({
          success: true,
          message: "Webhook already processed",
        });
      }

      await pool.query(
        `INSERT INTO webhook_events
                 (event_id, event_type)
                 VALUES ($1, $2)`,
        [eventId, eventType]
      );

      /* ---------------------------------------------
         PAYMENT CAPTURED
      --------------------------------------------- */

      if (eventType === "payment.captured") {
        const payment =
          payload?.payload?.payment?.entity;

        if (payment) {
          const orderId = payment.order_id;
          const paymentId = payment.id;

          const acquirerData =
            payment.acquirer_data || {};

          const utr =
            acquirerData.rrn ||
            acquirerData.bank_transaction_id ||
            acquirerData.transaction_id ||
            acquirerData.upi_transaction_id ||
            null;

          await pool.query(
            `UPDATE bookings
                         SET
                            razorpay_payment_id = COALESCE(
                                razorpay_payment_id,
                                $1
                            ),
                            utr = COALESCE(
                                utr,
                                $2
                            ),
                            payment_status = 'paid',
                            paid_at = COALESCE(
                                paid_at,
                                NOW()
                            )
                         WHERE razorpay_order_id = $3`,
            [
              paymentId,
              utr,
              orderId,
            ]
          );
        }
      }

      /* ---------------------------------------------
         PAYMENT FAILED
      --------------------------------------------- */

      if (eventType === "payment.failed") {
        const payment =
          payload?.payload?.payment?.entity;

        if (payment?.order_id) {
          await pool.query(
            `UPDATE bookings
                         SET payment_status = 'failed'
                         WHERE razorpay_order_id = $1
                           AND payment_status != 'paid'`,
            [payment.order_id]
          );
        }
      }

      return res.status(200).json({
        success: true,
      });

    } catch (error) {
      console.error("Webhook error:", error);

      return res.status(500).json({
        success: false,
        message: "Webhook processing failed",
      });
    }
  }
);

/* =========================================================
   JSON BODY
========================================================= */

app.use(express.json());

/* =========================================================
   STATIC FRONTEND
========================================================= */

app.use(express.static(path.join(__dirname, "public")));

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      database: "connected",
      razorpay: Boolean(
        RAZORPAY_KEY_ID &&
        RAZORPAY_KEY_SECRET
      ),
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      database: "error",
    });
  }
});

/* =========================================================
   PUBLIC CONFIG
========================================================= */

app.get("/api/config", (req, res) => {
  res.json({
    success: true,
    keyId: RAZORPAY_KEY_ID,
    event: {
      name: "Dandiya Raas",
      date: "14 October 2026",
      time: "6:30 PM",
      venue: "Beside PSF Ground, Kallur Layout, Hubli",
    },
    tickets: {
      stag: {
        name: TICKETS.stag.name,
        count: TICKETS.stag.count,
        amount: TICKETS.stag.amount,
      },

      couple: {
        name: TICKETS.couple.name,
        count: TICKETS.couple.count,
        amount: TICKETS.couple.amount,
      },

      group: {
        name: TICKETS.group.name,
        count: TICKETS.group.count,
        amount: TICKETS.group.amount,
      },
    },
  });
});

/* =========================================================
   CREATE ORDER
========================================================= */

app.post("/api/orders", async (req, res) => {
  try {
    const {
      ticketType,
      name,
      phone,
      email,
    } = req.body;

    if (!ticketType || !TICKETS[ticketType]) {
      return res.status(400).json({
        success: false,
        message: "Invalid ticket type",
      });
    }

    if (!name || !phone) {
      return res.status(400).json({
        success: false,
        message: "Name and phone are required",
      });
    }

    const ticket = TICKETS[ticketType];

    const bookingId = generateBookingId();

    /* ---------------------------------------------
       Create Razorpay order
    --------------------------------------------- */

    const order = await razorpay.orders.create({
      amount: ticket.amount,
      currency: "INR",
      receipt: bookingId,
      notes: {
        booking_id: bookingId,
        ticket_type: ticketType,
        customer_name: String(name),
        customer_phone: String(phone),
      },
    });

    /* ---------------------------------------------
       Save booking BEFORE returning order
    --------------------------------------------- */

    await pool.query(
      `INSERT INTO bookings
            (
                booking_id,
                ticket_type,
                ticket_name,
                ticket_count,
                amount,
                customer_name,
                customer_phone,
                customer_email,
                razorpay_order_id,
                payment_status
            )
            VALUES
            (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,'created'
            )`,
      [
        bookingId,
        ticketType,
        ticket.name,
        ticket.count,
        ticket.amount,
        String(name).trim(),
        String(phone).trim(),
        email ? String(email).trim() : null,
        order.id,
      ]
    );

    return res.json({
      success: true,

      bookingId,

      orderId: order.id,

      amount: order.amount,

      currency: order.currency,

      keyId: RAZORPAY_KEY_ID,

      ticket: {
        type: ticketType,
        name: ticket.name,
        count: ticket.count,
      },
    });

  } catch (error) {
    console.error("Create order error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create payment order",
    });
  }
});

/* =========================================================
   VERIFY PAYMENT
========================================================= */

app.post("/api/verify-payment", async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
    } = req.body;

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res.status(400).json({
        success: false,
        message: "Missing payment verification details",
      });
    }

    /* ---------------------------------------------
       Get booking from DB
    --------------------------------------------- */

    const bookingResult = await client.query(
      `SELECT *
             FROM bookings
             WHERE razorpay_order_id = $1
             FOR UPDATE`,
      [razorpay_order_id]
    );

    if (bookingResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }

    const booking = bookingResult.rows[0];

    /* ---------------------------------------------
       Prevent duplicate processing
    --------------------------------------------- */

    if (
      booking.payment_status === "paid" &&
      booking.razorpay_payment_id === razorpay_payment_id
    ) {
      return res.json({
        success: true,
        alreadyPaid: true,
        bookingId: booking.booking_id,
      });
    }

    /* ---------------------------------------------
       Verify Checkout signature
    --------------------------------------------- */

    const validSignature = verifyPaymentSignature(
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    );

    if (!validSignature) {
      return res.status(400).json({
        success: false,
        message: "Invalid Razorpay signature",
      });
    }

    /* ---------------------------------------------
       Fetch payment directly from Razorpay
    --------------------------------------------- */

    const payment = await razorpay.payments.fetch(
      razorpay_payment_id
    );

    /* ---------------------------------------------
       Verify order/payment relationship
    --------------------------------------------- */

    if (payment.order_id !== razorpay_order_id) {
      return res.status(400).json({
        success: false,
        message: "Payment does not belong to this order",
      });
    }

    /* ---------------------------------------------
       Verify amount
    --------------------------------------------- */

    if (Number(payment.amount) !== Number(booking.amount)) {
      return res.status(400).json({
        success: false,
        message: "Payment amount mismatch",
      });
    }

    /* ---------------------------------------------
       Verify captured status
    --------------------------------------------- */

    if (
      payment.status !== "captured" &&
      payment.captured !== true
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment is not captured yet",
      });
    }

    /* ---------------------------------------------
       Extract UTR/RRN where available
    --------------------------------------------- */

    const acquirerData =
      payment.acquirer_data || {};

    const utr =
      acquirerData.rrn ||
      acquirerData.bank_transaction_id ||
      acquirerData.transaction_id ||
      acquirerData.upi_transaction_id ||
      null;

    /* ---------------------------------------------
       Save payment
    --------------------------------------------- */

    await client.query(
      `UPDATE bookings
             SET
                razorpay_payment_id = $1,
                utr = COALESCE($2, utr),
                payment_status = 'paid',
                paid_at = COALESCE(paid_at, NOW())
             WHERE booking_id = $3`,
      [
        razorpay_payment_id,
        utr,
        booking.booking_id,
      ]
    );

    await client.query("COMMIT");

    return res.json({
      success: true,
      bookingId: booking.booking_id,
      paymentId: razorpay_payment_id,
      utr: utr,
    });

  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_) { }

    console.error("Verify payment error:", error);

    return res.status(500).json({
      success: false,
      message: "Payment verification failed",
    });

  } finally {
    client.release();
  }
});

/* =========================================================
   VERIFY UTR
========================================================= */

app.post("/api/verify-utr", async (req, res) => {
  try {
    const {
      bookingId,
      utr,
    } = req.body;

    if (!bookingId || !utr) {
      return res.status(400).json({
        success: false,
        message: "Booking ID and UTR are required",
      });
    }

    const cleanUtr = String(utr).trim();

    const result = await pool.query(
      `SELECT *
             FROM bookings
             WHERE booking_id = $1`,
      [bookingId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Booking not found",
      });
    }

    const booking = result.rows[0];

    if (booking.payment_status !== "paid") {
      return res.status(400).json({
        success: false,
        message: "Payment is not confirmed",
      });
    }

    /* ---------------------------------------------
       Duplicate UTR check
    --------------------------------------------- */

    const duplicate = await pool.query(
      `SELECT booking_id
             FROM bookings
             WHERE utr = $1
               AND booking_id != $2`,
      [
        cleanUtr,
        bookingId,
      ]
    );

    if (duplicate.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "This UTR has already been used",
      });
    }

    /* ---------------------------------------------
       If Razorpay already supplied the UTR,
       compare against it.
    --------------------------------------------- */

    if (
      booking.utr &&
      String(booking.utr) !== cleanUtr
    ) {
      return res.status(400).json({
        success: false,
        message: "UTR does not match the Razorpay payment",
      });
    }

    await pool.query(
      `UPDATE bookings
             SET utr = $1
             WHERE booking_id = $2`,
      [
        cleanUtr,
        bookingId,
      ]
    );

    return res.json({
      success: true,
      verified: true,
      bookingId,
    });

  } catch (error) {
    console.error("UTR verification error:", error);

    return res.status(500).json({
      success: false,
      message: "UTR verification failed",
    });
  }
});

/* =========================================================
   GET TICKET
========================================================= */

app.get("/api/ticket/:bookingId", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
                booking_id,
                ticket_type,
                ticket_name,
                ticket_count,
                customer_name,
                customer_phone,
                customer_email,
                amount,
                razorpay_order_id,
                razorpay_payment_id,
                utr,
                payment_status,
                created_at,
                paid_at
             FROM bookings
             WHERE booking_id = $1`,
      [req.params.bookingId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found",
      });
    }

    const booking = result.rows[0];

    if (booking.payment_status !== "paid") {
      return res.status(403).json({
        success: false,
        message: "Payment is not confirmed",
      });
    }

    return res.json({
      success: true,
      ticket: booking,
    });

  } catch (error) {
    console.error("Ticket fetch error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch ticket",
    });
  }
});

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* =========================================================
   LOCAL SERVER
========================================================= */

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(
      `Dandiya Raas server running on http://localhost:${PORT}`
    );
  });
}

module.exports = app;