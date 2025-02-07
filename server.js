const express = require("express");
const app = express();
const port = process.env.PORT || 3000;

const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

app.use(express.json());

const SECRET_KEY = "secret_key";

const users = []; // store users data (username and password)
const highScores = []; // store high scores from games

// user sign up
app.post(
  "/signup",
  [
    body("userHandle").isString().notEmpty().isLength({ min: 6 }),
    body("password").isString().notEmpty().isLength({ min: 6 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { userHandle, password } = req.body;

    const existingUser = users.find((user) => user.userHandle === userHandle);
    if (existingUser) {
      return res.status(409).json({ message: "username already exists" });
    }

    users.push({ userHandle, password });
    res.status(201).json({ message: "user registered successfully" });
  }
);

// login endpoint: generates JWT token
app.post(
  "/login",
  [
    body("userHandle").isString().notEmpty(),
    body("password").isString().notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // check for additional fields in the request
    const allowedFields = ["userHandle", "password"];
    const extraFields = Object.keys(req.body).filter(field => !allowedFields.includes(field));

    if (extraFields.length > 0) {
      return res.status(400).json({ message: "request contains additional fields: " + extraFields.join(", ") });
    }

    const { userHandle, password } = req.body;

    const user = users.find(
      (u) => u.userHandle === userHandle && u.password === password
    );
    if (!user) {
      return res.status(401).json({ message: "invalid credentials" });
    }

    const token = jwt.sign({ userHandle }, SECRET_KEY, { expiresIn: "1 hour" });
    res.status(200).json({ jsonWebToken: token });
  }
);

// verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "token required" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(401).json({ message: "invalid token" });
    req.user = user;
    next();
  });
}

// add high scores endpoint
app.post(
  "/high-scores",
  verifyToken,
  [
    body("level").isString().notEmpty(),
    body("userHandle").isString().notEmpty(),
    body("score").isInt({ min: 0 }),
    body("timestamp").isString().notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { level, userHandle, score, timestamp } = req.body;

    const newScore = {
      id: highScores.length + 1,
      level,
      userHandle,
      score,
      timestamp,
    };

    highScores.push(newScore);
    res.status(201).json(newScore);
  }
);

// retrieve high scores endpoint
app.get("/high-scores", (req, res) => {
  const { level, page = 1 } = req.query;

  let filteredScores = level
    ? highScores.filter((score) => score.level === level)
    : highScores;

  filteredScores.sort((a, b) => b.score - a.score);

  const pageSize = 20;
  const startIndex = (page - 1) * pageSize;
  const paginatedScores = filteredScores.slice(startIndex, startIndex + pageSize);

  res.json(paginatedScores);
});

let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};
