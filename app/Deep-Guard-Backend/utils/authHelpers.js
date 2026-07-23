const jwt = require("jsonwebtoken");
const crypto = require("crypto");
require("dotenv").config();

const COOKIE_OPTS = {
  httpOnly: true,
  secure: true,
  sameSite: "none",
  path: "/",
};

const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");

const createAccessToken = (userId, email, version) =>
  jwt.sign({ userId, email, tokenVersion: version }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });

const createRefreshToken = (userId, email, version, rememberMe = false) =>
  jwt.sign(
    { userId, email, tokenVersion: version, rememberMe },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: rememberMe ? "30d" : "1d" }
  );

const setAuthCookies = (res, access, refresh, rememberMe = false) => {
  const accessOpts = { ...COOKIE_OPTS };
  const refreshOpts = { ...COOKIE_OPTS };

  if (rememberMe) {
    accessOpts.maxAge = 15 * 60 * 1000; // 15m
    refreshOpts.maxAge = 30 * 24 * 60 * 60 * 1000; // 30d
  }

  res.cookie("accessToken", access, accessOpts);
  res.cookie("refreshToken", refresh, refreshOpts);

  // Always clear trial cookie upon setting real auth cookies
  res.clearCookie("trialAccess", COOKIE_OPTS);
};

const clearAuthCookies = (res) => {
  res.clearCookie("accessToken", COOKIE_OPTS);
  res.clearCookie("refreshToken", COOKIE_OPTS);
  res.clearCookie("trialAccess", COOKIE_OPTS);
};

module.exports = {
  COOKIE_OPTS,
  hashToken,
  createAccessToken,
  createRefreshToken,
  setAuthCookies,
  clearAuthCookies,
};
