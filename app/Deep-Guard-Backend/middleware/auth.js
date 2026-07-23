// middleware/auth.js
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { supabase } = require("../config/supabase");
const {
  COOKIE_OPTS,
  hashToken,
  createAccessToken,
  createRefreshToken,
  setAuthCookies,
  clearAuthCookies,
} = require("../utils/authHelpers");

const authMiddleware = async (req, res, next) => {
  try {
    const accessToken = req.cookies.accessToken || null;
    const refreshToken = req.cookies.refreshToken || null;
    const trialToken = req.cookies.trialAccess || null;

    let decoded = null;
    let rememberMe = false;

    // ----------------------------------------------------
    // 1. TRY STANDARD ACCESS TOKEN FIRST
    // ----------------------------------------------------
    if (accessToken) {
      try {
        decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
      } catch (err) {
        if (err.name !== "TokenExpiredError") {
          return res.status(401).json({
            code: "INVALID_ACCESS",
            message: "Invalid access token",
          });
        }
      }
    }

    // ----------------------------------------------------
    // 2. ACCESS TOKEN INVALID/EXPIRED → TRY REFRESH TOKEN
    // ----------------------------------------------------
    if (!decoded && refreshToken) {
      let refreshDecoded;
      try {
        refreshDecoded = jwt.verify(
          refreshToken,
          process.env.JWT_REFRESH_SECRET
        );
      } catch (err) {
        return res.status(401).json({
          code: "INVALID_REFRESH",
          message: "Session expired",
        });
      }

      const { userId, email, tokenVersion } = refreshDecoded;
      rememberMe = !!refreshDecoded.rememberMe;

      const hashedRT = hashToken(refreshToken);

      // Look up refresh session in DB
      const { data: session, error: sessionErr } = await supabase
        .from("sessions")
        .select("*")
        .eq("refresh_token_hash", hashedRT)
        .eq("user_id", userId)
        .single();

      if (sessionErr || !session) {
        return res.status(401).json({
          code: "REFRESH_NOT_FOUND",
          message: "Session expired",
        });
      }

      // Check DB expiration timestamp
      if (new Date(session.expires_at).getTime() < Date.now()) {
        await supabase.from("sessions").delete().eq("id", session.id);
        return res.status(401).json({
          code: "SESSION_EXPIRED",
          message: "Session expired",
        });
      }

      // Validate user existence and token_version
      const { data: userData, error: userErr } = await supabase
        .from("users")
        .select("id, name, email, profile_picture, token_version")
        .eq("id", userId)
        .single();

      if (userErr || !userData) {
        return res.status(401).json({
          code: "USER_NOT_FOUND",
          message: "User not found",
        });
      }

      if (userData.token_version !== tokenVersion) {
        await supabase.from("sessions").delete().eq("user_id", userId);
        return res.status(401).json({
          code: "TOKEN_VERSION_MISMATCH",
          message: "Session invalidated",
        });
      }

      // ----------------------------------------------------
      // 3. ROTATE REFRESH TOKEN (With Grace Period)
      // ----------------------------------------------------
      const newRefreshToken = createRefreshToken(
        userId,
        email,
        userData.token_version,
        rememberMe
      );

      const newHash = hashToken(newRefreshToken);

      // Create NEW session in DB
      await supabase.from("sessions").insert({
        user_id: userId,
        refresh_token_hash: newHash,
        token_version_snapshot: userData.token_version,
        user_agent: req.headers["user-agent"],
        ip_address: req.ip,
        expires_at: new Date(Date.now() + 30 * 86400000).toISOString(),
      });

      // Mark old session for deletion (Grace Period of 10 seconds)
      setTimeout(async () => {
        try {
          await supabase.from("sessions").delete().eq("id", session.id);
        } catch (e) {
          console.error("Failed to cleanup old session:", e);
        }
      }, 10000); // 10 seconds grace period

      // Issue NEW access token
      const newAccessToken = createAccessToken(
        userId,
        email,
        userData.token_version
      );

      setAuthCookies(res, newAccessToken, newRefreshToken, rememberMe);

      decoded = {
        userId,
        email,
        tokenVersion: userData.token_version,
      };
    }

    // ----------------------------------------------------
    // 4. IF STANDARD AUTHENTICATION SUCCEEDED
    // ----------------------------------------------------
    if (decoded) {
      const { data: user, error: userErr2 } = await supabase
        .from("users")
        .select("id, name, email, profile_picture, token_version")
        .eq("id", decoded.userId)
        .single();

      if (userErr2 || !user) {
        return res.status(401).json({
          code: "USER_NOT_FOUND",
          message: "User not found",
        });
      }

      if (user.token_version !== decoded.tokenVersion) {
        return res.status(401).json({
          code: "TOKEN_VERSION_MISMATCH",
          message: "Session invalidated",
        });
      }

      req.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        profile_pic: user.profile_picture,
        tokenVersion: user.token_version,
      };

      // Real user session takes priority -> clean up any guest trial token
      if (trialToken) {
        res.clearCookie("trialAccess", COOKIE_OPTS);
      }

      return next();
    }

    // ----------------------------------------------------
    // 5. IF NO STANDARD AUTH, FALLBACK TO GUEST TRIAL
    // ----------------------------------------------------
    if (trialToken) {
      try {
        const decodedTrial = jwt.verify(trialToken, process.env.JWT_SECRET);
        
        const { data: session, error } = await supabase
          .from("trial_sessions")
          .select("*")
          .eq("id", decodedTrial.sessionId)
          .single();

        if (error || !session) {
          res.clearCookie("trialAccess", COOKIE_OPTS);
          return res.status(401).json({
            code: "TRIAL_EXPIRED",
            message: "Trial expired. Sign in to continue.",
          });
        }

        // Expired?
        if (new Date(session.expires_at).getTime() <= Date.now()) {
          // Cleanup trial files and DB record
          try {
            const list = await supabase.storage.from("trial_analyses").list(session.id, {
              limit: 1000,
              offset: 0,
            });
            if (list.data && list.data.length > 0) {
              const paths = list.data.map((f) => `${session.id}/${f.name}`);
              await supabase.storage.from("trial_analyses").remove(paths);
            }
            await supabase.from("trial_sessions").delete().eq("id", session.id);
          } catch (e) {
            console.error("Trial session cleanup error:", e);
          }

          res.clearCookie("trialAccess", COOKIE_OPTS);
          return res.status(401).json({
            code: "TRIAL_EXPIRED",
            message: "Your trial has expired. Sign in to continue.",
          });
        }

        req.user = {
          id: 'trial_user',
          name: 'Guest User',
          email: 'guest@trial.com',
          isTrial: true,
          trialSessionId: decodedTrial.sessionId
        };
        return next();
      } catch (err) {
        res.clearCookie("trialAccess", COOKIE_OPTS);
      }
    }

    // ----------------------------------------------------
    // 6. ALL AUTHENTICATION METHODS FAILED
    // ----------------------------------------------------
    return res.status(401).json({
      code: "NO_TOKENS",
      message: "Not authorized",
    });

  } catch (err) {
    console.error("Auth middleware error:", err);
    return res.status(401).json({
      code: "SERVER_ERROR",
      message: "Not authorized",
    });
  }
};

module.exports = authMiddleware;
