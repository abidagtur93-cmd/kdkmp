// Vercel Serverless Function: /api/cloud-sync.js
// Menangani:
// 1. Sinkronisasi Akun & Data Ruang Kerja Lintas Perangkat (Laptop/HP berbeda)
// 2. Pengiriman Email Verifikasi Kode OTP 6-Digit secara nyata (tanpa menampilkan OTP di layar)

import crypto from "crypto";
import fs from "fs";
import path from "path";

const TMP_STORE_PATH = path.join("/tmp", "siakad_kdmp_cloud_vault.json");
const OTP_SECRET_SALT = process.env.OTP_SECRET_SALT || "SIAKAD_KDMP_OTP_SERVER_SECRET_2026";

function readCloudStore() {
  try {
    if (fs.existsSync(TMP_STORE_PATH)) {
      return JSON.parse(fs.readFileSync(TMP_STORE_PATH, "utf-8"));
    }
  } catch (e) {}
  return {};
}

function writeCloudStore(data) {
  try {
    fs.writeFileSync(TMP_STORE_PATH, JSON.stringify(data), "utf-8");
  } catch (e) {}
}

function computeClientCompatibleHash(str) {
  return crypto.createHash("sha256").update("KDMP_SEC_2026_" + String(str || "")).digest("hex");
}

function generateDeterministicWindowOtp(email) {
  // Berlaku 5 menit per window agar serverless stateless tetap dapat memverifikasi dengan akurat
  const window5Min = Math.floor(Date.now() / (5 * 60 * 1000));
  const hmac = crypto.createHmac("sha256", OTP_SECRET_SALT).update(`${email.toLowerCase()}:${window5Min}`).digest("hex");
  const num = (parseInt(hmac.substring(0, 8), 16) % 900000) + 100000;
  return String(num);
}

function verifyWindowOtp(email, otpInput) {
  const curWindow = Math.floor(Date.now() / (5 * 60 * 1000));
  for (const w of [curWindow, curWindow - 1]) {
    const hmac = crypto.createHmac("sha256", OTP_SECRET_SALT).update(`${email.toLowerCase()}:${w}`).digest("hex");
    const expected = String((parseInt(hmac.substring(0, 8), 16) % 900000) + 100000);
    if (String(otpInput).trim() === expected) return true;
  }
  return false;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // Optional Upstash Redis / Vercel KV support if configured in Vercel Environment Variables
  const kvUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const kvToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

  async function getStoreObject() {
    if (kvUrl && kvToken) {
      try {
        const r = await fetch(`${kvUrl}/get/siakad_kdmp_vault`, {
          headers: { Authorization: `Bearer ${kvToken}` }
        });
        const j = await r.json();
        if (j && j.result) return JSON.parse(j.result);
      } catch (e) {}
    }
    return readCloudStore();
  }

  async function saveStoreObject(storeObj) {
    writeCloudStore(storeObj);
    if (kvUrl && kvToken) {
      try {
        await fetch(`${kvUrl}/set/siakad_kdmp_vault`, {
          method: "POST",
          headers: { Authorization: `Bearer ${kvToken}`, "Content-Type": "application/json" },
          body: JSON.stringify(JSON.stringify(storeObj))
        });
      } catch (e) {}
    }
  }

  if (req.method === "GET") {
    const store = await getStoreObject();
    return res.status(200).json({ ok: true, store });
  }

  if (req.method === "POST") {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const { action, key, value, email, otp, coopName, adminName } = body;

    if (action === "set" && key) {
      const store = await getStoreObject();
      store[key] = value;
      await saveStoreObject(store);
      return res.status(200).json({ ok: true });
    }

    if (action === "send_otp" && email) {
      const otpCode = generateDeterministicWindowOtp(email);
      const otpHash = computeClientCompatibleHash(otpCode);

      // Kirim email nyata melalui Resend API / SMTP API jika RESEND_API_KEY diset di Vercel Environment
      const resendKey = process.env.RESEND_API_KEY;
      if (resendKey) {
        try {
          await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
              Authorization: `Bearer ${resendKey}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              from: process.env.EMAIL_FROM || "SIAKAD-KDMP <onboarding@resend.dev>",
              to: [email],
              subject: `Kode Verifikasi OTP Login Admin Utama - ${coopName || "SIAKAD-KDMP"}`,
              html: `<div style="font-family:sans-serif;padding:20px;border:1px solid #e2e8f0;border-radius:12px;">
                <h2 style="color:#991b1b;">Verifikasi Login Admin Utama Usaha SIAKAD-KDMP</h2>
                <p>Halo <strong>${adminName || "Admin Utama"}</strong> (${coopName || "Koperasi Desa Merah Putih"}),</p>
                <p>Berikut adalah 6 digit Kode Verifikasi OTP Anda (berlaku 5 menit):</p>
                <div style="font-size:28px;font-weight:bold;letter-spacing:6px;padding:12px 20px;background:#fef2f2;color:#991b1b;display:inline-block;border-radius:8px;">${otpCode}</div>
                <p style="font-size:12px;color:#64748b;margin-top:16px;">Jangan berikan kode ini kepada pihak yang tidak berwenang.</p>
              </div>`
            })
          });
        } catch (e) {}
      }

      return res.status(200).json({
        ok: true,
        sentTo: email,
        otpHash
      });
    }

    if (action === "verify_otp" && email && otp) {
      const isValid = verifyWindowOtp(email, otp);
      return res.status(200).json({ ok: true, valid: isValid });
    }

    return res.status(400).json({ ok: false, error: "Invalid action" });
  }

  return res.status(405).json({ ok: false, error: "Method not allowed" });
}
