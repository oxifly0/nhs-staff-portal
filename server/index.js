const express = require("express");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const fetch = require("node-fetch");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// ======================
// CONFIG
// ======================

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET not set");
}

const SECRET = process.env.JWT_SECRET;

// ======================
// MIDDLEWARE
// ======================

app.use(cors({
  origin: "https://oxifly0.github.io",
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

// Debug middleware
app.use((req, res, next) => {
  console.log("---- REQUEST ----");
  console.log(req.method, req.url);
  console.log("Cookies:", req.cookies);
  next();
});

// ======================
// SUPABASE
// ======================

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

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
    // Exchange code for access token
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
    if (!tokenData.access_token) {
      throw new Error("Discord token exchange failed");
    }

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

    // Find or create user
    let { data: users } = await supabase
      .from("users")
      .select("*")
      .eq("discord_id", discordUser.id)
      .limit(1);

    let user = users?.[0];

    if (!user) {
      const { data: newUser, error } = await supabase
        .from("users")
        .insert([{
          discord_id: discordUser.id,
          discord_username: `${discordUser.username}#${discordUser.discriminator}`,
          role: "clinical",
          approved: true // TEMP
        }])
        .select()
        .single();

      if (error) throw error;
      user = newUser;
    }

    // Issue JWT in HTTP-only cookie
    const jwtToken = jwt.sign(
      { id: user.id, role: user.role },
      SECRET,
      { expiresIn: "2h" }
    );

    res.cookie("auth", jwtToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 2 * 60 * 60 * 1000
    });

    // Redirect to frontend dashboard
    res.redirect(
      "https://oxifly0.github.io/nhs-staff-portal/dashboard.html"
    );

  } catch (err) {
    console.error(err);
    res.status(500).send("Discord login failed");
  }
});

// ======================
// AUTH MIDDLEWARE
// ======================

function requireAuth(req, res, next) {
  const token = req.cookies.auth;
  if (!token) return res.sendStatus(401);

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}

// ======================
// API ROUTES
// ======================

// WHO AM I
app.get("/me", requireAuth, (req, res) => {
  res.json(req.user);
});

// LIST STAFF (MANAGEMENT ONLY)
app.get("/staff", requireAuth, async (req, res) => {
  if (req.user.role !== "management") {
    return res.sendStatus(403);
  }

  const { data, error } = await supabase
    .from("users")
    .select("id, discord_username, role")
    .order("discord_username");

  if (error) return res.sendStatus(500);
  res.json(data);
});

// UPDATE STAFF ROLE
app.put("/staff/:id", requireAuth, async (req, res) => {
  if (req.user.role !== "management") {
    return res.sendStatus(403);
  }

  const { role } = req.body;
  const { id } = req.params;

  if (!["clinical", "management"].includes(role)) {
    return res.status(400).send("Invalid role");
  }

  const { error } = await supabase
    .from("users")
    .update({ role })
    .eq("id", id);

  if (error) return res.sendStatus(500);
  res.send("Role updated");
});

// LOGOUT
app.post("/logout", (req, res) => {
  res.clearCookie("auth", {
    httpOnly: true,
    secure: true,
    sameSite: "None"
  });
  res.sendStatus(200);
});

// ROOT
app.get("/", (req, res) => {
  res.send("NHS Staff Portal API – Cookie auth enabled");
});

// ======================
// START SERVER
// ======================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
