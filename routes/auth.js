const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");
const router = new express.Router();

// POST /login - login: {username, password} => {token}
router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const isValid = await User.authenticate(username, password);
    if (isValid) {
      await User.updateLoginTimestamp(username);
      const token = jwt.sign({ username }, SECRET_KEY);
      return res.json({ token });
    }
    return res.status(401).json({ message: "Invalid username/password" });
  } catch (err) {
    return next(err);
  }
});


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, phone } = req.body;
    const user = await User.register({ username, password, first_name, last_name, phone });
    await User.updateLoginTimestamp(username);
    const token = jwt.sign({ username: user.username }, SECRET_KEY);
    return res.json({ token });
  } catch (err) {
    return next(err);
  }
});


module.exports = router;