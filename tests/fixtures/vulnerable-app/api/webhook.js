const express = require("express");
const router = express.Router();

// Webhook handler with no signature verification: integ.webhook_sig FAIL
router.post("/api/webhook/stripe", async (req, res) => {
  const event = req.body;
  if (event.type === "checkout.session.completed") {
    await grantAccess(event.data.object.customer_email);
  }
  res.json({ received: true });
});
module.exports = router;
