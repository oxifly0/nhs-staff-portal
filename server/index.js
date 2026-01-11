const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fetch = require("node-fetch");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET not set");
}

const SECRET = process.env.JWT_SECRET;

// Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Debug middleware
app.use((req, res, next) => {
  console.log("---- REQUEST ----");
  console.log(req.method, req.url);
  console.log("Auth:", req.headers.authorization);
  next();
});


// ======================
// DISCORD OAUTH
// ======================

// Start Discord login
app.get("/auth/discord", (req, res) => {
  const redirect =
    "https://discord.com/oauth2/authorize" +
    `?client_id=${process.env.DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}` +
    "&response_type=code" +
    "&scope=identify";

  res.redirect(redirect);
});

// Discord callback
app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("No code");

  try {
    // Exchange code for token
    const tokenRes = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: process.env.DISCORD_CLIENT_ID,
          client_secret: process.env.DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: process.env.DISCORD_REDIRECT_URI
        })
      }
    );

    const tokenData = await tokenRes.json();

    // Get Discord user
    const userRes = await fetch(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`
        }
      }
    );

    const discordUser = await userRes.json();

    // Find user in DB
    let { data: users } = await supabase
      .from("users")
      .select("*")
      .eq("discord_id", discordUser.id)
      .limit(1);

    let user = users?.[0];

    // Create user if new
    if (!user) {
      const { data: newUser, error } = await supabase
        .from("users")
        .insert([{
          discord_id: discordUser.id,
          discord_username: `${discordUser.username}#${discordUser.discriminator}`,
          role: "clinical",
          approved: true // TEMP (approval later)
        }])
        .select()
        .single();

      if (error) throw error;
      user = newUser;
    }

    // Issue JWT
    const jwtToken = jwt.sign(
      {
        id: user.id,
        role: user.role,
        discord_id: user.discord_id
      },
      SECRET,
      { expiresIn: "2h" }
    );

    // Redirect to frontend
    res.redirect(
      `/oauth-success.html?token=${jwtToken}&role=${user.role}`
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("Discord login failed");
  }
});


// ======================
// AUTH HELPERS
// ======================

function getToken(req) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.split(" ")[1];
}


// ======================
// API ROUTES
// ======================

// WHO AM I
app.get("/me", (req, res) => {
  const token = getToken(req);
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET);
    res.json(decoded);
  } catch {
    res.sendStatus(401);
  }
});

// LIST STAFF (MANAGEMENT ONLY)
app.get("/staff", async (req, res) => {
  const token = getToken(req);
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== "management") return res.sendStatus(403);

    const { data, error } = await supabase
      .from("users")
      .select("id, discord_username, role")
      .order("discord_username");

    if (error) throw error;
    res.json(data);
  } catch {
    res.sendStatus(401);
  }
});

// UPDATE STAFF ROLE
app.put("/staff/:id", async (req, res) => {
  const token = getToken(req);
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== "management") return res.sendStatus(403);

    const { role } = req.body;
    const { id } = req.params;

    if (!["clinical", "management"].includes(role)) {
      return res.status(400).send("Invalid role");
    }

    const { error } = await supabase
      .from("users")
      .update({ role })
      .eq("id", id);

    if (error) throw error;
    res.send("Role updated");
  } catch {
    res.sendStatus(401);
  }
});


// ROOT
app.get("/", (req, res) => {
  res.send("NHS Staff Portal API – Discord OAuth enabled");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
