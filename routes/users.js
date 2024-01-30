const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('users', { user: req.idtoken, at: req.at });
});

module.exports = router;