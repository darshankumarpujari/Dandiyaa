const express = require("express");
const path = require("path");
const crypto = require("crypto");
const Razorpay = require("razorpay");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================================
   ENVIRONMENT VARIABLES
========================================================= */

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const CHECKIN_SECRET = process.env.CHECKIN_SECRET;

/* =========================================================
   EVENT
========================================================= */

const EVENT = {
  name: "Dandiya Raas",
  date: "14 October 2026",
  time: "5:30 PM onwards",
  venue: "Beside PSF Ground, Kallur Layout, Hubli",
};

/* =========================================================
   TICKET TYPES
   Amounts are in PAISE.
========================================================= */

const TICKETS = {
  stag: {
    name: "Stag Entry",
    people: 1,
    amount: 29900,
  },

  couple: {
    name: "Couple Entry",
    people: 2,
    amount: 49900,
  },

  group: {
    name: "Group of Five",
    people: 5,
    amount: 109900,
  },
};

/* =========================================================
   DATABASE
========================================================= */

const pool = DATABASE_URL
  ? new Pool({
    connectionString: DATABASE_URL,
    ssl: {
      rejectUnauthorized: false,
    },
    max: 5,
  })
  : null;

/* =========================================================
   RAZORPAY
========================================================= */

const razorpay =
  RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET
    ? new Razorpay({
      key_id: RAZORPAY_KEY_ID,
      key_secret: RAZORPAY_KEY_SECRET,
    })
    : null;

/* =========================================================
   HELPERS
========================================================= */

function generateBookingId() {
  return `DR26-${crypto
    .randomBytes(6)
    .toString("hex")
    .toUpperCase()}`;
}

function generateTicketToken() {
  return crypto.randomBytes(32).toString("hex");
}

function safeCompare(a, b) {
  if (!a || !b) return false;

  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  if (aa.length !== bb.length) return false;

  return crypto.timingSafeEqual(aa, bb);
}

function verifyPaymentSignature(
  orderId,
  paymentId,
  signature
) {
  if (!RAZORPAY_KEY_SECRET) return false;

  const expected = crypto
    .createHmac(
      "sha256",
      RAZORPAY_KEY_SECRET
    )
    .update(`${orderId}|${paymentId}`)
    .digest("hex");

  return safeCompare(expected, signature);
}

function verifyWebhookSignature(
  rawBody,
  signature
) {
  if (!WEBHOOK_SECRET || !signature) {
    return false;
  }

  const expected = crypto
    .createHmac(
      "sha256",
      WEBHOOK_SECRET
    )
    .update(rawBody)
    .digest("hex");

  return safeCompare(expected, signature);
}

function requireDatabase(res) {
  if (!pool) {
    res.status(500).json({
      success: false,
      error:
        "DATABASE_URL is missing in Vercel Environment Variables.",
    });

    return false;
  }

  return true;
}

function requireRazorpay(res) {
  if (!razorpay) {
    res.status(500).json({
      success: false,
      error:
        "Razorpay credentials are missing in Vercel Environment Variables.",
    });

    return false;
  }

  return true;
}

/* =========================================================
   BUILD PUBLIC TICKET
========================================================= */

function buildTicketResponse(booking) {
  const ticket = TICKETS[booking.ticket_type];

  const quantity = Number(
    booking.ticket_count
  );

  return {
    bookingId: booking.booking_id,

    name: booking.customer_name,

    phone: booking.customer_phone,

    email:
      booking.customer_email || "",

    ticket:
      booking.ticket_name,

    ticketType:
      booking.ticket_type,

    quantity,

    admits: ticket
      ? ticket.people * quantity
      : quantity,

    amount:
      Number(booking.amount) / 100,

    paymentId:
      booking.razorpay_payment_id,

    paymentStatus:
      booking.payment_status,

    event: EVENT.name,

    date: EVENT.date,

    time: EVENT.time,

    venue: EVENT.venue,

    checkedInAt:
      booking.checked_in_at || null,
  };
}

/* =========================================================
   WEBHOOK
   MUST COME BEFORE express.json()
========================================================= */

app.post(
  "/api/webhook",

  express.raw({
    type: "application/json",
  }),

  async (req, res) => {
    if (!pool) {
      return res.status(500).json({
        success: false,
        error: "Database is not configured.",
      });
    }

    const client = await pool.connect();

    try {
      const signature =
        req.headers["x-razorpay-signature"];

      if (!signature) {
        return res.status(400).json({
          success: false,
          error:
            "Missing Razorpay webhook signature.",
        });
      }

      if (
        !verifyWebhookSignature(
          req.body,
          signature
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid Razorpay webhook signature.",
        });
      }

      const payload = JSON.parse(
        req.body.toString("utf8")
      );

      const eventType =
        payload.event || "unknown";

      const payment =
        payload?.payload?.payment?.entity ||
        null;

      const orderId =
        payment?.order_id || null;

      const paymentId =
        payment?.id || null;

      const eventId =
        req.headers["x-razorpay-event-id"] ||
        (
          paymentId
            ? `${eventType}:${paymentId}`
            : crypto
              .createHash("sha256")
              .update(req.body)
              .digest("hex")
        );

      await client.query("BEGIN");

      /* Prevent duplicate webhook processing */

      const duplicate =
        await client.query(
          `SELECT id
           FROM webhook_events
           WHERE event_id = $1`,
          [eventId]
        );

      if (duplicate.rows.length > 0) {
        await client.query("ROLLBACK");

        return res.status(200).json({
          success: true,
          message:
            "Webhook already processed.",
        });
      }

      /* =====================================================
         PAYMENT CAPTURED
      ===================================================== */

      if (
        eventType === "payment.captured" &&
        payment &&
        orderId &&
        paymentId
      ) {
        const result =
          await client.query(
            `SELECT *
             FROM bookings
             WHERE razorpay_order_id = $1
             FOR UPDATE`,
            [orderId]
          );

        if (result.rows.length > 0) {
          const booking =
            result.rows[0];

          /* Verify amount */

          if (
            Number(payment.amount) !==
            Number(booking.amount)
          ) {
            await client.query(
              "ROLLBACK"
            );

            return res.status(400).json({
              success: false,
              error:
                "Webhook payment amount mismatch.",
            });
          }

          const ticketToken =
            booking.ticket_token ||
            generateTicketToken();

          await client.query(
            `UPDATE bookings
             SET
               razorpay_payment_id = $1,
               payment_status = 'paid',
               ticket_token =
                 COALESCE(ticket_token, $2),
               paid_at =
                 COALESCE(paid_at, NOW())
             WHERE booking_id = $3`,
            [
              paymentId,
              ticketToken,
              booking.booking_id,
            ]
          );
        }
      }

      /* =====================================================
         PAYMENT FAILED
      ===================================================== */

      if (
        eventType === "payment.failed" &&
        orderId
      ) {
        await client.query(
          `UPDATE bookings
           SET payment_status = 'failed'
           WHERE razorpay_order_id = $1
             AND payment_status <> 'paid'`,
          [orderId]
        );
      }

      /* Save webhook event */

      await client.query(
        `INSERT INTO webhook_events
         (event_id, event_type)
         VALUES ($1, $2)`,
        [
          eventId,
          eventType,
        ]
      );

      await client.query("COMMIT");

      return res.status(200).json({
        success: true,
      });

    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) { }

      console.error(
        "WEBHOOK ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Webhook processing failed.",
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   JSON
========================================================= */

app.use(
  express.json({
    limit: "1mb",
  })
);

/* =========================================================
   STATIC FRONTEND
========================================================= */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get(
  "/api/health",
  async (req, res) => {
    try {
      if (!pool) {
        return res.status(500).json({
          success: false,
          database:
            "not configured",
          razorpay: Boolean(
            razorpay
          ),
        });
      }

      await pool.query(
        "SELECT 1"
      );

      return res.json({
        success: true,
        database:
          "connected",
        razorpay:
          Boolean(razorpay),
      });

    } catch (error) {
      console.error(
        "HEALTH ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        database:
          "connection failed",
        razorpay:
          Boolean(razorpay),
        error:
          error.message,
      });
    }
  }
);

/* =========================================================
   PUBLIC CONFIG
========================================================= */

app.get(
  "/api/config",
  (req, res) => {
    res.json({
      success: true,

      keyId:
        RAZORPAY_KEY_ID,

      event: EVENT,

      tickets:
        Object.fromEntries(
          Object.entries(
            TICKETS
          ).map(
            ([id, ticket]) => [
              id,
              {
                name:
                  ticket.name,

                people:
                  ticket.people,

                amount:
                  ticket.amount /
                  100,
              },
            ]
          )
        ),
    });
  }
);

/* =========================================================
   CREATE RAZORPAY ORDER
========================================================= */

app.post(
  "/api/orders",
  async (req, res) => {
    try {
      if (
        !requireDatabase(res) ||
        !requireRazorpay(res)
      ) {
        return;
      }

      const name =
        String(
          req.body.name || ""
        ).trim();

      const phone =
        String(
          req.body.phone || ""
        ).trim();

      const email =
        String(
          req.body.email || ""
        ).trim();

      const type =
        String(
          req.body.type || ""
        ).trim();

      const quantity = Math.max(
        1,
        Math.min(
          10,
          parseInt(
            req.body.qty,
            10
          ) || 1
        )
      );

      /* Validate name */

      if (name.length < 2) {
        return res.status(400).json({
          success: false,
          error:
            "Enter a valid full name.",
        });
      }

      /* Validate phone */

      if (
        !/^[6-9]\d{9}$/.test(
          phone
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Enter a valid 10-digit mobile number.",
        });
      }

      /* Validate email */

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          email
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Enter a valid email address.",
        });
      }

      const ticket =
        TICKETS[type];

      if (!ticket) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid ticket type.",
        });
      }

      /* Calculate amount */

      const amountPaise =
        ticket.amount *
        quantity;

      /* Generate booking ID */

      const bookingId =
        generateBookingId();

      /* Create Razorpay order */

      const razorpayOrder =
        await razorpay.orders.create(
          {
            amount:
              amountPaise,

            currency: "INR",

            receipt:
              bookingId,

            notes: {
              booking_id:
                bookingId,

              ticket_type:
                type,

              quantity:
                String(
                  quantity
                ),

              customer_name:
                name,

              customer_phone:
                phone,
            },
          }
        );

      /* Save booking */

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
          $1,$2,$3,$4,$5,
          $6,$7,$8,$9,'created'
        )`,
        [
          bookingId,
          type,
          ticket.name,
          quantity,
          amountPaise,
          name,
          phone,
          email,
          razorpayOrder.id,
        ]
      );

      return res.json({
        success: true,

        bookingId,

        orderId:
          razorpayOrder.id,

        amount:
          amountPaise / 100,

        currency: "INR",

        keyId:
          RAZORPAY_KEY_ID,
      });

    } catch (error) {
      console.error(
        "CREATE ORDER ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error?.error
            ?.description ||
          error?.message ||
          "Could not create payment order.",
      });
    }
  }
);

/* =========================================================
   VERIFY PAYMENT
   This is what creates/releases the ticket.
========================================================= */

app.post(
  "/api/verify-payment",
  async (req, res) => {
    if (
      !requireDatabase(res) ||
      !requireRazorpay(res)
    ) {
      return;
    }

    const client =
      await pool.connect();

    try {
      const {
        bookingId,
        razorpay_order_id,
        razorpay_payment_id,
        razorpay_signature,
      } = req.body;

      if (
        !bookingId ||
        !razorpay_order_id ||
        !razorpay_payment_id ||
        !razorpay_signature
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Missing payment verification details.",
        });
      }

      await client.query(
        "BEGIN"
      );

      /* Find booking */

      const bookingResult =
        await client.query(
          `SELECT *
           FROM bookings
           WHERE booking_id = $1
             AND razorpay_order_id = $2
           FOR UPDATE`,
          [
            bookingId,
            razorpay_order_id,
          ]
        );

      if (
        bookingResult.rows
          .length === 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          error:
            "Booking not found.",
        });
      }

      let booking =
        bookingResult.rows[0];

      /* Already paid */

      if (
        booking.payment_status ===
        "paid"
      ) {
        if (
          booking.razorpay_payment_id !==
          razorpay_payment_id
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            success: false,
            error:
              "This booking has already been paid.",
          });
        }

        const ticketToken =
          booking.ticket_token ||
          generateTicketToken();

        if (
          !booking.ticket_token
        ) {
          const updated =
            await client.query(
              `UPDATE bookings
               SET ticket_token = $1
               WHERE booking_id = $2
               RETURNING *`,
              [
                ticketToken,
                booking.booking_id,
              ]
            );

          booking =
            updated.rows[0];
        }

        await client.query(
          "COMMIT"
        );

        return res.json({
          success: true,
          alreadyPaid: true,
          bookingId:
            booking.booking_id,
          paymentId:
            booking.razorpay_payment_id,
          ticketToken,
          ticket:
            buildTicketResponse(
              booking
            ),
        });
      }

      /* Verify Razorpay signature */

      const validSignature =
        verifyPaymentSignature(
          razorpay_order_id,
          razorpay_payment_id,
          razorpay_signature
        );

      if (!validSignature) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          error:
            "Invalid Razorpay payment signature.",
        });
      }

      /* Prevent payment reuse */

      const duplicatePayment =
        await client.query(
          `SELECT booking_id
           FROM bookings
           WHERE razorpay_payment_id = $1
             AND booking_id <> $2`,
          [
            razorpay_payment_id,
            booking.booking_id,
          ]
        );

      if (
        duplicatePayment.rows
          .length > 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          success: false,
          error:
            "This Razorpay payment is already linked to another booking.",
        });
      }

      /* Fetch payment from Razorpay */

      const payment =
        await razorpay.payments.fetch(
          razorpay_payment_id
        );

      /* Verify order */

      if (
        payment.order_id !==
        razorpay_order_id
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          error:
            "Payment does not belong to this order.",
        });
      }

      /* Verify currency */

      if (
        payment.currency !==
        "INR"
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          error:
            "Payment currency mismatch.",
        });
      }

      /* Verify amount */

      if (
        Number(
          payment.amount
        ) !==
        Number(
          booking.amount
        )
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          error:
            "Payment amount does not match the booking.",
        });
      }

      /* Verify captured */

      if (
        payment.status !==
        "captured" &&
        payment.captured !==
        true
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          error:
            "Payment has not been captured yet.",
        });
      }

      /* Generate secure ticket token */

      const ticketToken =
        booking.ticket_token ||
        generateTicketToken();

      /* Mark booking paid */

      const updated =
        await client.query(
          `UPDATE bookings
           SET
             razorpay_payment_id = $1,
             payment_status = 'paid',
             ticket_token =
               COALESCE(
                 ticket_token,
                 $2
               ),
             paid_at =
               COALESCE(
                 paid_at,
                 NOW()
               )
           WHERE booking_id = $3
           RETURNING *`,
          [
            razorpay_payment_id,
            ticketToken,
            booking.booking_id,
          ]
        );

      booking =
        updated.rows[0];

      await client.query(
        "COMMIT"
      );

      /* Return ticket information */

      return res.json({
        success: true,

        bookingId:
          booking.booking_id,

        paymentId:
          razorpay_payment_id,

        ticketToken,

        ticket:
          buildTicketResponse(
            booking
          ),
      });

    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) { }

      console.error(
        "VERIFY PAYMENT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error?.message ||
          "Payment verification failed.",
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   VERIFY TICKET USING QR TOKEN
========================================================= */

app.get("/api/ticket/verify/:bookingId", async (req, res) => {
  try {
    const bookingId = String(req.params.bookingId || "").trim();

    if (!bookingId) {
      return res.status(400).json({
        valid: false,
        error: "Booking ID is required."
      });
    }

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
                payment_status,
                created_at,
                paid_at
             FROM bookings
             WHERE booking_id = $1`,
      [bookingId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        valid: false,
        error: "Ticket not found."
      });
    }

    const booking = result.rows[0];

    /*
     * Payment must be successfully completed.
     */

    if (booking.payment_status !== "paid") {
      return res.status(403).json({
        valid: false,
        error: "Payment has not been confirmed."
      });
    }

    /*
     * Ticket is valid.
     */

    return res.status(200).json({
      valid: true,

      ticket: {
        bookingId: booking.booking_id,

        name: booking.customer_name,

        phone: booking.customer_phone,

        email: booking.customer_email,

        ticketType: booking.ticket_name,

        quantity: booking.ticket_count,

        amount: Number(booking.amount) / 100,

        paymentStatus: booking.payment_status,

        paymentId: booking.razorpay_payment_id,

        paidAt: booking.paid_at
      }
    });

  } catch (error) {

    console.error(
      "Ticket verification error:",
      error
    );

    return res.status(500).json({
      valid: false,
      error: "Unable to verify ticket."
    });
  }
});
/* =========================================================
   CHECK-IN TICKET
========================================================= */

app.post(
  "/api/ticket/check-in/:token",
  async (req, res) => {
    if (
      !requireDatabase(res)
    ) {
      return;
    }

    if (!CHECKIN_SECRET) {
      return res.status(500).json({
        success: false,
        error:
          "CHECKIN_SECRET is not configured.",
      });
    }

    const suppliedSecret =
      req.headers[
      "x-checkin-secret"
      ];

    if (
      !safeCompare(
        suppliedSecret,
        CHECKIN_SECRET
      )
    ) {
      return res.status(401).json({
        success: false,
        error:
          "Unauthorized.",
      });
    }

    const client =
      await pool.connect();

    try {
      const token =
        String(
          req.params.token ||
          ""
        ).trim();

      await client.query(
        "BEGIN"
      );

      const result =
        await client.query(
          `SELECT *
           FROM bookings
           WHERE ticket_token = $1
           FOR UPDATE`,
          [token]
        );

      if (
        result.rows.length ===
        0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          error:
            "Ticket not found.",
        });
      }

      const booking =
        result.rows[0];

      if (
        booking.payment_status !==
        "paid"
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(403).json({
          success: false,
          error:
            "Payment is not confirmed.",
        });
      }

      /* Prevent duplicate entry */

      if (
        booking.checked_in_at
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          success: false,

          alreadyCheckedIn:
            true,

          bookingId:
            booking.booking_id,

          checkedInAt:
            booking.checked_in_at,

          error:
            "This ticket has already been checked in.",
        });
      }

      const updated =
        await client.query(
          `UPDATE bookings
           SET checked_in_at = NOW()
           WHERE booking_id = $1
           RETURNING checked_in_at`,
          [booking.booking_id]
        );

      await client.query(
        "COMMIT"
      );

      const ticket =
        TICKETS[
        booking.ticket_type
        ];

      return res.json({
        success: true,

        message:
          "ENTRY ALLOWED",

        bookingId:
          booking.booking_id,

        customerName:
          booking.customer_name,

        ticket:
          booking.ticket_name,

        admits: ticket
          ? ticket.people *
          Number(
            booking.ticket_count
          )
          : Number(
            booking.ticket_count
          ),

        checkedInAt:
          updated.rows[0]
            .checked_in_at,
      });

    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) { }

      console.error(
        "CHECK-IN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Unable to check in ticket.",
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   GET TICKET USING BOOKING ID
========================================================= */

app.get(
  "/api/ticket/:bookingId",
  async (req, res) => {
    if (
      !requireDatabase(res)
    ) {
      return;
    }

    try {
      const bookingId =
        String(
          req.params.bookingId ||
          ""
        ).trim();

      const result =
        await pool.query(
          `SELECT *
           FROM bookings
           WHERE booking_id = $1`,
          [bookingId]
        );

      if (
        result.rows.length ===
        0
      ) {
        return res.status(404).json({
          success: false,
          error:
            "Ticket not found.",
        });
      }

      const booking =
        result.rows[0];

      if (
        booking.payment_status !==
        "paid"
      ) {
        return res.status(403).json({
          success: false,
          error:
            "Payment is not confirmed.",
        });
      }

      return res.json({
        success: true,

        ticket:
          buildTicketResponse(
            booking
          ),
      });

    } catch (error) {
      console.error(
        "GET TICKET ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          "Unable to fetch ticket.",
      });
    }
  }
);


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
          paid_at,
          checked_in,
          checked_in_at
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
   STAFF BOOKING VERIFICATION
========================================================= */

app.get("/api/staff/booking/:bookingId", async (req, res) => {
  try {

    const bookingId =
      String(req.params.bookingId || "").trim();

    if (!bookingId) {
      return res.status(400).json({
        valid: false,
        error: "Booking ID is required."
      });
    }

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
          payment_status,
          created_at,
          paid_at,
          checked_in,
          checked_in_at
       FROM bookings
       WHERE booking_id = $1`,
      [bookingId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        valid: false,
        error: "Booking ID not found."
      });
    }

    const booking = result.rows[0];

    if (booking.payment_status !== "paid") {
      return res.status(403).json({
        valid: false,
        error: "Payment has not been confirmed."
      });
    }

    return res.json({
      valid: true,
      ticket: booking
    });

  } catch (error) {

    console.error(
      "Staff booking verification error:",
      error
    );

    return res.status(500).json({
      valid: false,
      error: "Unable to verify booking."
    });
  }
});


/* =========================================================
   STAFF CHECK-IN
========================================================= */

app.post("/api/staff/checkin", async (req, res) => {

  const client = await pool.connect();

  try {

    const bookingId =
      String(
        req.body?.bookingId || ""
      ).trim();

    if (!bookingId) {

      return res.status(400).json({
        success: false,
        error: "Booking ID is required."
      });
    }

    await client.query("BEGIN");

    /*
     * Lock this booking so two staff members
     * cannot check it in simultaneously.
     */

    const result =
      await client.query(
        `SELECT
            booking_id,
            customer_name,
            payment_status,
            checked_in,
            checked_in_at
         FROM bookings
         WHERE booking_id = $1
         FOR UPDATE`,
        [bookingId]
      );

    if (result.rows.length === 0) {

      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        error: "Ticket not found."
      });
    }

    const booking = result.rows[0];

    if (
      booking.payment_status !== "paid"
    ) {

      await client.query("ROLLBACK");

      return res.status(403).json({
        success: false,
        error: "Payment has not been confirmed."
      });
    }

    if (booking.checked_in) {

      await client.query("ROLLBACK");

      return res.status(409).json({
        success: false,
        alreadyCheckedIn: true,
        error:
          "This ticket has already been checked in."
      });
    }

    await client.query(
      `UPDATE bookings
       SET
          checked_in = TRUE,
          checked_in_at = NOW()
       WHERE booking_id = $1`,
      [bookingId]
    );

    await client.query("COMMIT");

    return res.json({
      success: true,
      bookingId,
      customerName:
        booking.customer_name,
      message:
        "Customer checked in successfully."
    });

  } catch (error) {

    try {
      await client.query("ROLLBACK");
    } catch (_) { }

    console.error(
      "Staff check-in error:",
      error
    );

    return res.status(500).json({
      success: false,
      error: "Check-in failed."
    });

  } finally {

    client.release();

  }
});

/* =========================================================
   FRONTEND FALLBACK
   Express 5 syntax — DO NOT use app.get("*")
========================================================= */
app.get("/staff", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "staff.html")
  );
});


app.get(
  "/{*splat}",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================================================
   LOCAL SERVER
========================================================= */

if (
  require.main === module
) {
  app.listen(
    PORT,
    () => {
      console.log(
        `Dandiya Raas server running on http://localhost:${PORT}`
      );
    }
  );
}

module.exports = app;