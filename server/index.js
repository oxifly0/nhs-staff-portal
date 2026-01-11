const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = process.env.JWT_SECRET || "game-secret";

const { createClient } = require("@supabase/supabase-js");

app.use((req, res, next) => {
  console.log("---- INCOMING REQUEST ----");
  console.log("URL:", req.method, req.url);
  console.log("Authorization header:", req.headers.authorization);
  next();
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const { data: rows, error } = await supabase
  .from("users")
  .select("*")
  .eq("username", username)
  .limit(1);

    if (!rows || rows.length === 0)
      return res.status(401).send("Invalid login");

    const user = rows[0];

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid)
      return res.status(401).send("Invalid login");

    const token = jwt.sign(
      { id: user.id, role: user.role },
      SECRET,
      { expiresIn: "2h" }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).send("Missing fields");

    if (password.length < 8)
      return res.status(400).send("Password too short");

    const password_hash = await bcrypt.hash(password, 10);

    const { error } = await supabase.from("users").insert([
      {
        username,
        password_hash,
        role: "clinical" // default role
      }
    ]);

    if (error) {
      return res.status(400).send("User already exists");
    }

    res.send("Account created");
  } catch {
    res.status(500).send("Server error");
  }
});


// LIST STAFF (MANAGEMENT ONLY)
app.get("/staff", async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== "management") {
      return res.sendStatus(403);
    }

    const { data, error } = await supabase
      .from("users")
      .select("id, username, role")
      .order("username");

    if (error) {
      console.error(error);
      return res.sendStatus(500);
    }

    res.json(data);
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
});



// UPDATE STAFF ROLE (MANAGEMENT ONLY)
app.put("/staff/:id", async (req, res) => {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== "management") return res.sendStatus(403);

    const { role } = req.body;
    const { id } = req.params;

    const { error } = await supabase
      .from("users")
      .update({ role })
      .eq("id", id);

    if (error) return res.sendStatus(500);

    res.send("Role updated");
  } catch {
    res.sendStatus(401);
  }
});



// WHO AM I
app.get("/me", (req, res) => {
  const token = req.headers.authorization;

  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET);
    res.json(decoded);
  } catch {
    res.sendStatus(401);
  }
});


app.get("/", (req, res) => {
  res.send("St Nicholas University Hospitals NHS Trust – Staff Portal API is online! :)");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
