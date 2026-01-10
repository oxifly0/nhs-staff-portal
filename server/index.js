const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = process.env.JWT_SECRET || "game-secret";

let users = [
  {
    username: "manager",
    password: bcrypt.hashSync("password123", 10),
    role: "management"
  }
];

// LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).send("Invalid login");

  const token = jwt.sign(
    { username: user.username, role: user.role },
    SECRET
  );

  res.json({ token, role: user.role });
});

// MANAGEMENT: ADD STAFF
app.post("/staff", (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwt.verify(token, SECRET);

  if (decoded.role !== "management")
    return res.sendStatus(403);

  users.push(req.body);
  res.send("Staff added");
});

app.listen(3000);