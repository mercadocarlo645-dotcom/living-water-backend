
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const admin = require('firebase-admin');
const fs = require('fs');
const os = require('os');

const app = express();

app.use(express.json({ limit: '2mb' }));
app.use(cors());

const PORT = process.env.PORT || 3000;
const OTP_SALT = process.env.OTP_SALT;

const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL;
const BREVO_SENDER_NAME =
  process.env.BREVO_SENDER_NAME || 'Living Water System';

// ==========================================
// STARTUP CONFIGURATION CHECKS
// ==========================================

if (!OTP_SALT || OTP_SALT.length < 32) {
  console.error('[CONFIG ERROR] OTP_SALT must be at least 32 characters.');
  process.exit(1);
}

if (!BREVO_API_KEY || !BREVO_SENDER_EMAIL) {
  console.error('[CONFIG ERROR] BREVO_API_KEY and BREVO_SENDER_EMAIL are required.');
  process.exit(1);
}

// ==========================================
// FIREBASE ADMIN INITIALIZATION
// ==========================================

try {
  if (!admin.apps.length) {
    let serviceAccountPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;

    if (
      !serviceAccountPath ||
      !fs.existsSync(serviceAccountPath)
    ) {
      const defaultKeyPath = path.join(
        __dirname,
        'livingwater2-firebase-adminsdk-fbsvc-50a01b892e.json'
      );

      if (fs.existsSync(defaultKeyPath)) {
        serviceAccountPath = defaultKeyPath;
      }
    }

    if (serviceAccountPath && fs.existsSync(serviceAccountPath)) {
      const absolutePath = path.isAbsolute(serviceAccountPath)
        ? serviceAccountPath
        : path.join(__dirname, serviceAccountPath);

      const serviceAccount = require(absolutePath);

      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        databaseURL: 'https://livingwater2-default-rtdb.firebaseio.com/',
      });

      console.log('[FIREBASE] Initialized using service account.');
    } else {
      admin.initializeApp({
        databaseURL: 'https://livingwater2-default-rtdb.firebaseio.com/',
      });

      console.log('[FIREBASE] Initialized using default credentials.');
    }
  }
} catch (error) {
  console.error('[FIREBASE ERROR]', error.message);
  process.exit(1);
}

const db = admin.database();

// ==========================================
// GENERAL HELPERS
// ==========================================

function sanitizeEmail(email) {
  return email.trim().toLowerCase().replace(/[.#$\/\[\]]/g, '_');
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function hashOtp(email, otpCode) {
  const cleanEmail = email.trim().toLowerCase();

  return crypto
    .createHmac('sha256', OTP_SALT)
    .update(`${cleanEmail}:${otpCode}`)
    .digest('hex');
}

function isValidPasswordFormat(password) {
  if (!password || password.length < 8 || password.length > 16) {
    return false;
  }

  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNum = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  return hasUpper && hasLower && hasNum && hasSpecial;
}

// ==========================================
// BREVO EMAIL SENDER
// ==========================================

async function sendGmailOtpEmail({ toEmail, otpCode, purpose }) {
  let subjectText = `Living Water - Verification Code: ${otpCode}`;

  if (purpose === 'admin_password_reset') {
    subjectText = `Living Water - Admin Password Reset Code: ${otpCode}`;
  } else if (purpose === 'admin_creation') {
    subjectText = `Living Water - Admin Account Verification Code: ${otpCode}`;
  } else if (purpose === 'driver_creation') {
    subjectText = `Living Water - Driver Account Verification Code: ${otpCode}`;
  } else if (purpose === 'cashier_creation') {
    subjectText = `Living Water - Cashier Account Verification Code: ${otpCode}`;
  }

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
      <h2 style="color: #0288d1; text-align: center;">Living Water System</h2>

      <p>Hello,</p>
      <p>Your One-Time Password (OTP) for account verification is:</p>

      <div style="text-align: center; margin: 30px 0;">
        <span style="font-size: 34px; font-weight: bold; letter-spacing: 6px; background: #e1f5fe; color: #0288d1; padding: 12px 24px; border-radius: 8px; display: inline-block;">
          ${otpCode}
        </span>
      </div>

      <p>This OTP is valid for <strong>5 minutes</strong>. Do not share this code with anyone.</p>

      <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />

      <p style="font-size: 12px; color: #777; text-align: center;">
        If you did not request this, please ignore this email.
      </p>
    </div>
  `;

  const response = await fetch(
    'https://api.brevo.com/v3/smtp/email',
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'api-key': BREVO_API_KEY,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        sender: {
          name: BREVO_SENDER_NAME,
          email: BREVO_SENDER_EMAIL,
        },
        to: [{ email: toEmail }],
        subject: subjectText,
        htmlContent,
      }),
    }
  );

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error('[BREVO ERROR]', response.status, result);
    throw new Error('Failed to send OTP email through Brevo.');
  }

  console.log('[BREVO SUCCESS] OTP email accepted for delivery.');
}

// ==========================================
// STRICT ADMIN EMAIL VERIFICATION
// ==========================================

async function isStrictAdminEmail(email) {
  const cleanEmail = email.trim().toLowerCase();
  const sanitized = sanitizeEmail(cleanEmail);
  const username = cleanEmail.split('@')[0];

  if (cleanEmail === 'mercadocarlo645@gmail.com') {
    return true;
  }

  try {
    const adminSnap = await db.ref(`admins_by_email/${sanitized}`).get();

    if (adminSnap.exists() && adminSnap.val()) {
      const val = adminSnap.val();

      if (val.role === 'Admin' || val.email === cleanEmail) {
        return true;
      }
    }
  } catch (_) {}

  try {
    const adminUserSnap = await db.ref(`admins_by_email/${username}`).get();

    if (adminUserSnap.exists() && adminUserSnap.val()) {
      const val = adminUserSnap.val();

      if (val.role === 'Admin' || val.email === cleanEmail) {
        return true;
      }
    }
  } catch (_) {}

  try {
    const usersSnap = await db.ref('users').get();

    if (usersSnap.exists() && usersSnap.val()) {
      const usersMap = usersSnap.val();

      for (const uid in usersMap) {
        const user = usersMap[uid];

        if (
          user &&
          (user.email || '').trim().toLowerCase() === cleanEmail
        ) {
          return (user.role || '').toLowerCase() === 'admin';
        }
      }
    }
  } catch (_) {}

  try {
    const userRecord = await admin.auth().getUserByEmail(cleanEmail);
    const userSnap = await db.ref(`users/${userRecord.uid}`).get();

    if (userSnap.exists() && userSnap.val()) {
      return (userSnap.val().role || '').toLowerCase() === 'admin';
    }
  } catch (_) {}

  return false;
}

// ==========================================
// OTP SEND
// POST /otp/send
// ==========================================

async function handleSendOtp(req, res) {
  try {
    const { email, purpose } = req.body;

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or missing email address.',
      });
    }

    const allowedPurposes = [
      'registration',
      'login',
      'password_reset',
      'admin_password_reset',
      'change_password',
      'driver_creation',
      'cashier_creation',
      'admin_creation',
    ];

    if (!purpose || !allowedPurposes.includes(purpose)) {
      return res.status(400).json({
        success: false,
        error: 'Unsupported OTP purpose.',
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const sanitized = sanitizeEmail(cleanEmail);
    const now = Date.now();

    if (purpose === 'admin_password_reset') {
      const isAdmin = await isStrictAdminEmail(cleanEmail);

      if (!isAdmin) {
        return res.status(403).json({
          success: false,
          error: 'Access Denied: The entered email address is not registered as an Admin account.',
        });
      }
    }

    const otpRef = db.ref(`otps/${sanitized}`);
    const snap = await otpRef.get();
    const data = snap.exists() ? snap.val() : null;

    let sendsCount = 0;
    const windowStart = now;

    if (data) {
      sendsCount = data.sendsCount || 0;

      if (sendsCount >= 3) {
        return res.status(429).json({
          success: false,
          error: 'Maximum OTP resend limit reached.',
        });
      }

      if (data.lastSentAt && now - data.lastSentAt < 60 * 1000) {
        const waitSecs = Math.ceil(
          (60 * 1000 - (now - data.lastSentAt)) / 1000
        );

        return res.status(429).json({
          success: false,
          error: `Please wait ${waitSecs}s before requesting a new OTP.`,
        });
      }
    }

    const otpCode = crypto.randomInt(100000, 1000000).toString();
    const hashed = hashOtp(cleanEmail, otpCode);
    const expiresAt = now + 5 * 60 * 1000;

    sendsCount += 1;

    await otpRef.set({
      hash: hashed,
      expiresAt,
      attempts: 0,
      sendsCount,
      windowStart,
      lastSentAt: now,
      purpose,
    });

    await sendGmailOtpEmail({
      toEmail: cleanEmail,
      otpCode,
      purpose,
    });

    return res.json({
      success: true,
      message: 'OTP sent successfully.',
      sendsRemaining: Math.max(0, 3 - sendsCount),
    });
  } catch (error) {
    console.error('[OTP SEND ERROR]', error.message);

    return res.status(500).json({
      success: false,
      error: 'Failed to send OTP email. Please try again later.',
    });
  }
}

// ==========================================
// OTP VERIFY
// POST /otp/verify
// ==========================================

async function handleVerifyOtp(req, res) {
  try {
    const { email, otpCode, purpose } = req.body;

    if (
      !email ||
      !isValidEmail(email) ||
      !otpCode ||
      !/^\d{6}$/.test(String(otpCode))
    ) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email or OTP code.',
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const sanitized = sanitizeEmail(cleanEmail);
    const now = Date.now();

    const otpRef = db.ref(`otps/${sanitized}`);
    const snap = await otpRef.get();

    if (!snap.exists()) {
      return res.status(400).json({
        success: false,
        error: 'No active OTP found. Please request a new code.',
      });
    }

    const data = snap.val();

    if (now > data.expiresAt) {
      await otpRef.remove();

      return res.status(400).json({
        success: false,
        error: 'OTP has expired. Please request a new code.',
      });
    }

    if (data.attempts >= 3) {
      await otpRef.remove();

      return res.status(429).json({
        success: false,
        error: 'Maximum verification attempts exceeded. Request a new OTP.',
      });
    }

    if (purpose && data.purpose !== purpose) {
      return res.status(400).json({
        success: false,
        error: 'OTP purpose does not match.',
      });
    }

    const hashedInput = hashOtp(cleanEmail, String(otpCode));

    if (hashedInput !== data.hash) {
      const attempts = (data.attempts || 0) + 1;

      await otpRef.update({ attempts });

      return res.status(400).json({
        success: false,
        error: `Incorrect OTP. ${Math.max(0, 3 - attempts)} attempts remaining.`,
      });
    }

    await otpRef.remove();

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const sessionExpiresAt = now + 15 * 60 * 1000;

    await db.ref(`verified_sessions/${sanitized}`).set({
      token: verificationToken,
      expiresAt: sessionExpiresAt,
      email: cleanEmail,
      purpose: purpose || data.purpose || 'registration',
    });

    return res.json({
      success: true,
      message: 'OTP verified successfully.',
      verificationToken,
    });
  } catch (error) {
    console.error('[OTP VERIFY ERROR]', error.message);

    return res.status(500).json({
      success: false,
      error: 'Internal server error during verification.',
    });
  }
}

// ==========================================
// ADMIN PASSWORD RESET
// POST /admin/password-reset
// ==========================================

async function handleAdminPasswordReset(req, res) {
  try {
    const { email, newPassword, verificationToken } = req.body;

    if (
      !email ||
      !isValidEmail(email) ||
      !newPassword ||
      !verificationToken
    ) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: email, newPassword, verificationToken.',
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const sanitized = sanitizeEmail(cleanEmail);
    const username = cleanEmail.split('@')[0];
    const now = Date.now();

    const sessionRef = db.ref(`verified_sessions/${sanitized}`);
    const snap = await sessionRef.get();

    if (!snap.exists()) {
      return res.status(400).json({
        success: false,
        error: 'Email verification required. Please verify OTP first.',
      });
    }

    const sessionData = snap.val();

    if (
      now > sessionData.expiresAt ||
      sessionData.token !== verificationToken ||
      sessionData.purpose !== 'admin_password_reset'
    ) {
      await sessionRef.remove();

      return res.status(400).json({
        success: false,
        error: 'Verification session expired or invalid. Please repeat verification.',
      });
    }

    const isAdmin = await isStrictAdminEmail(cleanEmail);

    if (!isAdmin) {
      await sessionRef.remove();

      return res.status(403).json({
        success: false,
        error: 'Access Denied: The email account is not registered as an Admin.',
      });
    }

    if (!isValidPasswordFormat(newPassword)) {
      return res.status(400).json({
        success: false,
        error: 'Password must be 8–16 characters and contain uppercase, lowercase, number, and special character.',
      });
    }

    let userRecord;

    try {
      userRecord = await admin.auth().getUserByEmail(cleanEmail);
    } catch (_) {
      return res.status(404).json({
        success: false,
        error: 'Admin Firebase Authentication account was not found.',
      });
    }

    await admin.auth().updateUser(userRecord.uid, {
      password: newPassword,
    });

    await sessionRef.remove();

    const nowIso = new Date().toISOString();

    // Do not save passwords in Realtime Database.
    const updates = {
      updatedAt: nowIso,
    };

    await db.ref(`admins_by_email/${sanitized}`).update(updates).catch(() => {});
    await db.ref(`admins_by_email/${username}`).update(updates).catch(() => {});
    await db.ref(`users/${userRecord.uid}`).update(updates).catch(() => {});

    console.log('[ADMIN PW RESET] Password updated through Firebase Authentication.');

    return res.json({
      success: true,
      message: 'Admin password updated successfully. You can now log in with your new password.',
    });
  } catch (error) {
    console.error('[ADMIN PASSWORD RESET ERROR]', error.message);

    return res.status(500).json({
      success: false,
      error: 'Failed to reset admin password. Please try again later.',
    });
  }
}

// ==========================================
// CUSTOMER REGISTRATION
// POST /register/complete
// ==========================================

async function handleCompleteRegistration(req, res) {
  try {
    const {
      email,
      password,
      name,
      phoneNumber,
      address,
      verificationToken,
    } = req.body;

    if (
      !email ||
      !isValidEmail(email) ||
      !password ||
      !name ||
      !verificationToken
    ) {
      return res.status(400).json({
        success: false,
        error: 'Missing required registration fields or verification token.',
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 6 characters long.',
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanName = name.trim();
    const cleanPhone = (phoneNumber || '').trim();
    const cleanAddress = (address || '').trim();
    const sanitized = sanitizeEmail(cleanEmail);

    const sessionRef = db.ref(`verified_sessions/${sanitized}`);
    const snap = await sessionRef.get();

    if (!snap.exists()) {
      return res.status(400).json({
        success: false,
        error: 'Email verification required. Please verify OTP first.',
      });
    }

    const sessionData = snap.val();

    if (
      Date.now() > sessionData.expiresAt ||
      sessionData.token !== verificationToken ||
      sessionData.purpose !== 'registration'
    ) {
      await sessionRef.remove();

      return res.status(400).json({
        success: false,
        error: 'Verification session expired or invalid. Please repeat verification.',
      });
    }

    let userRecord;

    try {
      userRecord = await admin.auth().getUserByEmail(cleanEmail);
    } catch (_) {
      userRecord = null;
    }

    function formatE164Phone(phone) {
      if (!phone) return null;

      let clean = phone.trim().replace(/[^\d+]/g, '');

      if (clean.startsWith('09') && clean.length === 11) {
        clean = '+63' + clean.substring(1);
      } else if (clean.startsWith('639') && clean.length === 12) {
        clean = '+' + clean;
      } else if (!clean.startsWith('+')) {
        clean = '+' + clean;
      }

      return /^\+[1-9]\d{6,14}$/.test(clean) ? clean : null;
    }

    if (userRecord) {
      return res.status(409).json({
        success: false,
        error: 'An account with this email already exists.',
      });
    }

    const e164Phone = formatE164Phone(cleanPhone);

    const authParams = {
      email: cleanEmail,
      password,
      displayName: cleanName,
    };

    if (e164Phone) {
      authParams.phoneNumber = e164Phone;
    }

    try {
      userRecord = await admin.auth().createUser(authParams);
    } catch (createErr) {
      if (authParams.phoneNumber) {
        delete authParams.phoneNumber;
        userRecord = await admin.auth().createUser(authParams);
      } else {
        throw createErr;
      }
    }

    const uid = userRecord.uid;

    const userData = {
      uid,
      email: cleanEmail,
      role: 'Customer',
      name: cleanName,
      phoneNumber: cleanPhone,
      address: cleanAddress,
      createdAt: new Date().toISOString(),
    };

    await db.ref(`users/${uid}`).set(userData);

    const customerId = `CUST-${uid.substring(0, 6).toUpperCase()}`;

    await db.ref(`customers/${uid}`).set({
      customerId,
      uid,
      name: cleanName,
      email: cleanEmail,
      phoneNumber: cleanPhone,
      address: cleanAddress,
      ordersCount: 0,
      totalSpent: 0.0,
      joined: new Date().toISOString().split('T')[0],
    });

    await sessionRef.remove();

    return res.json({
      success: true,
      message: 'Registration completed successfully.',
      uid,
    });
  } catch (error) {
    console.error('[REGISTER COMPLETE ERROR]', error.message);

    return res.status(500).json({
      success: false,
      error: error.message || 'Failed to complete registration.',
    });
  }
}

// ==========================================
// SESSION CREATE
// POST /session/create
// ==========================================

async function handleCreateSessionCookie(req, res) {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({
        success: false,
        error: 'Missing ID token.',
      });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const expiresIn = 24 * 60 * 60 * 1000;

    const sessionCookie = await admin.auth().createSessionCookie(
      idToken,
      { expiresIn }
    );

    const isProduction = process.env.NODE_ENV === 'production';

    res.cookie('session', sessionCookie, {
      maxAge: expiresIn,
      httpOnly: true,
      secure: isProduction,
      sameSite: 'strict',
      path: '/',
    });

    return res.json({
      success: true,
      message: 'Session cookie created successfully.',
      uid: decodedToken.uid,
      expiresIn,
    });
  } catch (error) {
    console.error('[SESSION CREATE ERROR]', error.message);

    return res.status(401).json({
      success: false,
      error: 'Unauthorized ID token.',
    });
  }
}

// ==========================================
// SESSION VERIFY
// GET /session/verify
// ==========================================

async function handleVerifySessionCookie(req, res) {
  try {
    const cookieHeader = req.headers.cookie || '';
    let sessionCookie = '';

    const matches = cookieHeader.match(/session=([^;]+)/);

    if (matches && matches[1]) {
      sessionCookie = matches[1];
    } else if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer ')
    ) {
      sessionCookie = req.headers.authorization.split('Bearer ')[1];
    }

    if (!sessionCookie) {
      return res.status(401).json({
        success: false,
        error: 'No active session cookie found.',
      });
    }

    const decodedClaims = await admin.auth().verifySessionCookie(
      sessionCookie,
      true
    );

    return res.json({
      success: true,
      uid: decodedClaims.uid,
      email: decodedClaims.email,
    });
  } catch (error) {
    console.error('[SESSION VERIFY ERROR]', error.message);

    return res.status(401).json({
      success: false,
      error: 'Session cookie expired or invalid.',
    });
  }
}

// ==========================================
// SESSION LOGOUT
// POST /session/logout
// ==========================================

async function handleSessionLogout(req, res) {
  try {
    const cookieHeader = req.headers.cookie || '';
    let sessionCookie = '';

    const matches = cookieHeader.match(/session=([^;]+)/);

    if (matches && matches[1]) {
      sessionCookie = matches[1];
    }

    if (sessionCookie) {
      try {
        const decodedClaims = await admin.auth().verifySessionCookie(
          sessionCookie
        );

        await admin.auth().revokeRefreshTokens(decodedClaims.uid);
      } catch (_) {}
    }

    res.clearCookie('session', { path: '/' });

    return res.json({
      success: true,
      message: 'Session logged out successfully.',
    });
  } catch (error) {
    console.error('[SESSION LOGOUT ERROR]', error.message);

    return res.status(500).json({
      success: false,
      error: 'Failed to clear session.',
    });
  }
}

// ==========================================
// HARDWARE GPS UPDATE
// POST /api/gps/update
// ==========================================

async function handleHardwareGpsUpdate(req, res) {
  try {
    const {
      apiKey,
      driverId,
      orderId,
      latitude,
      longitude,
      speed,
      heading,
      source,
      deviceId,
    } = req.body;

    const expectedKey = process.env.GPS_API_KEY;

    if (!expectedKey) {
      console.error('[GPS CONFIG ERROR] GPS_API_KEY is missing.');

      return res.status(503).json({
        success: false,
        error: 'GPS service is not configured.',
      });
    }

    if (!apiKey || apiKey !== expectedKey) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or missing GPS API key.',
      });
    }

    if (!driverId || latitude == null || longitude == null) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: driverId, latitude, longitude.',
      });
    }

    const latNum = Number(latitude);
    const lngNum = Number(longitude);

    if (
      !Number.isFinite(latNum) ||
      !Number.isFinite(lngNum) ||
      Math.abs(latNum) > 90 ||
      Math.abs(lngNum) > 180
    ) {
      return res.status(400).json({
        success: false,
        error: 'Invalid GPS coordinates provided.',
      });
    }

    const cleanDriverId = String(driverId).replaceAll('#', '').trim();
    const cleanOrderId = String(orderId || '').replaceAll('#', '').trim();
    const nowIso = new Date().toISOString();

    const gpsPayload = {
      orderId: cleanOrderId,
      driverId: cleanDriverId,
      deviceId: deviceId || `ESP32_${cleanDriverId}`,
      latitude: latNum,
      longitude: lngNum,
      lat: latNum,
      lng: lngNum,
      speed: Number.isFinite(Number(speed)) ? Number(speed) : 0,
      heading: Number.isFinite(Number(heading)) ? Number(heading) : 0,
      locationSource: source || 'ESP32_HARDWARE',
      trackingStatus: 'active',
      timestamp: nowIso,
      updatedAt: nowIso,
    };

    await db.ref(`driverLocations/${cleanDriverId}`).set(gpsPayload);

    await db.ref(`drivers/${cleanDriverId}`).update({
      lat: latNum,
      lng: lngNum,
      latitude: latNum,
      longitude: lngNum,
      locationSource: source || 'ESP32_HARDWARE',
      lastLocationUpdate: nowIso,
    });

    if (cleanOrderId) {
      await db.ref(`delivery_tracking/${cleanOrderId}`).update({
        driverLat: latNum,
        driverLng: lngNum,
        driverLatitude: latNum,
        driverLongitude: lngNum,
        driverTrackingStatus: 'active',
        speed: gpsPayload.speed,
        updatedAt: nowIso,
      });
    }

    return res.json({
      success: true,
      message: 'Hardware GPS location recorded successfully.',
      driverId: cleanDriverId,
      timestamp: nowIso,
    });
  } catch (error) {
    console.error('[HARDWARE GPS UPDATE ERROR]', error.message);

    return res.status(500).json({
      success: false,
      error: 'Failed to process hardware GPS telemetry.',
    });
  }
}

// ==========================================
// ORDER PAYMENT ELIGIBILITY
// POST /api/orders/validate-eligibility
// ==========================================

async function handleValidateOrderEligibility(req, res) {
  try {
    const {
      customerId,
      paymentMethod,
      paymentImage,
      totalAmount,
    } = req.body;

    if (!customerId) {
      return res.status(400).json({
        success: false,
        error: 'Missing required customerId.',
      });
    }

    const cleanUid = customerId.trim();

    const ordersSnap = await db.ref('orders').get();
    let qualifyingOrders = 0;

    if (ordersSnap.exists() && ordersSnap.val()) {
      const ordersMap = ordersSnap.val();

      for (const orderKey in ordersMap) {
        const order = ordersMap[orderKey];

        if (
          order &&
          (
            order.customerId === cleanUid ||
            (order.customerId || '').toLowerCase() === cleanUid.toLowerCase()
          )
        ) {
          const rawStatus = (
            order.status ||
            order.orderStatus ||
            order.deliveryStatus ||
            ''
          ).trim().toLowerCase();

          const isDelivered =
            rawStatus === 'delivered' || rawStatus === 'completed';

          const isCancelled = [
            'cancelled',
            'canceled',
            'rejected',
          ].includes(rawStatus);

          if (isDelivered && !isCancelled) {
            const method = (order.paymentMethod || '').toLowerCase();
            const payStatus = (order.paymentStatus || '').trim().toLowerCase();

            let paymentVerified = false;

            if (
              method.includes('qr') ||
              method.includes('gcash') ||
              method.includes('upload')
            ) {
              paymentVerified =
                payStatus === 'paid' || payStatus === 'verified';
            } else {
              paymentVerified = ![
                'pending',
                'unpaid',
                'rejected',
                'pending verification',
              ].includes(payStatus);
            }

            if (paymentVerified) {
              qualifyingOrders++;
            }
          }
        }
      }
    }

    const hasCompletedFirstOrder = qualifyingOrders >= 1;

    const custSnap = await db.ref(`customers/${cleanUid}`).get();

    let custData = custSnap.exists() ? custSnap.val() : null;

    if (!custData) {
      const userSnap = await db.ref(`users/${cleanUid}`).get();

      if (userSnap.exists()) {
        custData = userSnap.val();
      }
    }

    const isCreditEligible = custData
      ? (custData.creditEligible || custData.utangApproved || false)
      : false;

    const creditLimit = custData
      ? (parseFloat(custData.creditLimit) || 1000.0)
      : 1000.0;

    const debtsSnap = await db.ref('customerDebts').get();
    let outstandingDebt = 0.0;

    if (debtsSnap.exists() && debtsSnap.val()) {
      const debtsMap = debtsSnap.val();

      for (const dKey in debtsMap) {
        const debt = debtsMap[dKey];

        if (debt && debt.customerId === cleanUid) {
          const status = (debt.status || '').toUpperCase();

          if (status !== 'PAID') {
            const remaining = parseFloat(debt.remainingBalance) || 0.0;

            if (remaining > 0) {
              outstandingDebt += remaining;
            }
          }
        }
      }
    }

    if (paymentMethod) {
      const methodLower = paymentMethod.toLowerCase();

      const isGcash =
        methodLower.includes('qr') ||
        methodLower.includes('gcash') ||
        methodLower.includes('upload');

      const isCod =
        methodLower.includes('cash on delivery') ||
        methodLower === 'cod';

      const isUtang =
        methodLower.includes('utang') ||
        methodLower.includes('credit');

      if (!hasCompletedFirstOrder && (!isGcash || isCod || isUtang)) {
        return res.status(403).json({
          success: false,
          allowed: false,
          error: 'GCash is required for your first order. Cash on Delivery and Credit will become available after your first order is successfully completed.',
          hasCompletedFirstOrder,
        });
      }

      if (isGcash && (!paymentImage || !paymentImage.trim())) {
        return res.status(400).json({
          success: false,
          allowed: false,
          error: 'Please upload a clear image of your GCash payment confirmation receipt before submitting.',
        });
      }

      if (isUtang) {
        if (!hasCompletedFirstOrder) {
          return res.status(403).json({
            success: false,
            allowed: false,
            error: 'Cash on Delivery and Credit / Utang will become available after your first order is successfully completed.',
          });
        }

        if (!isCreditEligible) {
          return res.status(403).json({
            success: false,
            allowed: false,
            error: 'Utang / Credit is not enabled for your account. Contact Admin for approval.',
          });
        }

        const orderAmt = parseFloat(totalAmount) || 0.0;

        if (outstandingDebt + orderAmt > creditLimit) {
          return res.status(403).json({
            success: false,
            allowed: false,
            error: `Order amount exceeds your permitted credit limit (₱${creditLimit}). Current outstanding debt: ₱${outstandingDebt}.`,
          });
        }
      }
    }

    return res.json({
      success: true,
      allowed: true,
      hasCompletedFirstOrder,
      isCreditEligible,
      creditLimit,
      outstandingDebt,
      qualifyingOrdersCount: qualifyingOrders,
    });
  } catch (error) {
    console.error('[ORDER ELIGIBILITY VALIDATE ERROR]', error.message);

    return res.status(500).json({
      success: false,
      error: 'Internal server error during eligibility check.',
    });
  }
}

// ==========================================
// API ROUTES
// ==========================================

// =========================
// API ROUTES
// =========================

app.post('/otp/send', handleSendOtp);
app.post('/otp/verify', handleVerifyOtp);

app.post('/admin/verify-role', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        isAdmin: false,
        error: 'Invalid email address.',
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const isAdmin = await isStrictAdminEmail(cleanEmail);

    return res.json({
      success: true,
      isAdmin,
      message: isAdmin
        ? 'Admin account verified.'
        : 'This email is not registered as an Admin account.',
    });
  } catch (error) {
    console.error('[ADMIN ROLE VERIFY ERROR]', error.message);

    return res.status(500).json({
      success: false,
      isAdmin: false,
      error: 'Failed to verify Admin account.',
    });
  }
});

app.post('/admin/password-reset', handleAdminPasswordReset);
app.post('/register/complete', handleCompleteRegistration);

// Ilagay rito ang iba mo pang existing routes:
app.post('/session/create', handleCreateSessionCookie);
app.get('/session/verify', handleVerifySessionCookie);
app.post('/session/logout', handleSessionLogout);
app.post('/api/gps/update', handleHardwareGpsUpdate);
app.post('/api/orders/validate-eligibility', handleValidateOrderEligibility);

// ==========================================
// HEALTH CHECK
// ==========================================

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Living Water Backend',
    timestamp: new Date().toISOString(),
  });
});

// ==========================================
// LOCAL NETWORK INFORMATION
// ==========================================

function getLocalIpAddresses() {
  const interfaces = os.networkInterfaces();
  const ips = [];

  for (const name of Object.keys(interfaces)) {
    for (const net of interfaces[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        ips.push(`http://${net.address}:${PORT}`);
      }
    }
  }

  return ips;
}

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {
  console.log(`[SERVER] Living Water Backend running on port ${PORT}`);

  // Publish local URLs only when explicitly enabled.
  // Cloud hosting should use the Render service URL instead.
  if (process.env.PUBLISH_LOCAL_SERVER_URLS === 'true') {
    try {
      const localIps = getLocalIpAddresses();

      if (localIps.length > 0) {
        db.ref('server_config').set({
          backend_url: localIps[0],
          active_urls: localIps,
          port: PORT,
          updatedAt: new Date().toISOString(),
        }).then(() => {
          console.log('[CONFIG] Published local backend URLs.');
        }).catch((error) => {
          console.error('[CONFIG ERROR]', error.message);
        });
      }
    } catch (error) {
      console.error('[CONFIG ERROR]', error.message);
    }
  }
});
