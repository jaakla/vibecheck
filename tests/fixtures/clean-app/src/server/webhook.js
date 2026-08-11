const express = require("express");
const Stripe = require("stripe");
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const router = express.Router();

router.post("/api/webhook/stripe", express.raw({ type: "application/json" }), (req, res) => {
  let event;
  try {
    // Signature verified before any side effect.
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).send("invalid signature");
  }
  if (event.type === "checkout.session.completed") grantAccess(event);
  res.json({ received: true });
});
module.exports = router;
