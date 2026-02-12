import express from "express";
import axios from "axios";
import crypto from "crypto";

// =====================================================
// ENV (Render)
// =====================================================
const PORT = process.env.PORT || 3000;

// WhatsApp Cloud API
const WA_TOKEN = process.env.WA_TOKEN; // Permanent token
const PHONE_NUMBER_ID = process.env.PHONE_NUMBER_ID; // WhatsApp phone number ID
const VERIFY_TOKEN = process.env.VERIFY_TOKEN; // Webhook verify token
const META_APP_SECRET = process.env.META_APP_SECRET || ""; // Optional (signature verify)

// OpenAI
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4.1-mini";

// Branding / Ops
const BRAND_NAME = process.env.BRAND_NAME || "Tekko";
const ADMIN_PHONE = process.env.ADMIN_PHONE || ""; // e.g. 1809XXXXXXX (digits only preferred)
const DEFAULT_COUNTRY_HINT = process.env.DEFAULT_COUNTRY_HINT || "República Dominicana";

// =====================================================
// ✅ BOTHUB (NEW) - mínimos para conectar al Hub
// =====================================================
const BOTHUB_WEBHOOK_URL = process.env.BOTHUB_WEBHOOK_URL || ""; // URL completa: .../api/webhooks/webhook/:botId
const BOTHUB_WEBHOOK_SECRET = process.env.BOTHUB_WEBHOOK_SECRET || "";
const BOTHUB_TIMEOUT_MS = Number(process.env.BOTHUB_TIMEOUT_MS || 6000);

// =====================================================
// Stable stringify para que firma HMAC sea igual al Hub
// =====================================================
function stableStringify(obj: any) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(",")}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",")}}`;
}

function bothubHmacStable(payload: any, secret: string) {
  const raw = stableStringify(payload);
  return crypto.createHmac("sha256", secret).update(raw).digest("hex");
}

function bothubHmacJson(payload: any, secret: string) {
  // por si BOTHUB (server) firma con JSON.stringify normal
  return crypto.createHmac("sha256", secret).update(JSON.stringify(payload)).digest("hex");
}

// ✅ NEW: acepta varias formas de header de firma (por compatibilidad)
// - X-HUB-SIGNATURE
// - x-hub-signature
// - X-Hub-Signature / x-hub-signature
// - X-HUB-SIGNATURE-256 / X-Hub-Signature-256 (por si alguien lo manda así)
// y permite formato "sha256=<hex>" o "<hex>"
function getHubSignature(req: any) {
  const h =
    req.get("X-HUB-SIGNATURE") ||
    req.get("x-hub-signature") ||
    req.get("X-Hub-Signature") ||
    req.get("x-hub-signature") ||
    req.get("X-HUB-SIGNATURE-256") ||
    req.get("X-Hub-Signature-256") ||
    req.get("x-hub-signature-256") ||
    "";

  const sig = String(h || "").trim();
  if (!sig) return "";
  return sig.startsWith("sha256=") ? sig.slice("sha256=".length) : sig;
}

function timingSafeEqualHex(aHex: any, bHex: any) {
  const a = Buffer.from(String(aHex || ""), "utf8");
  const b = Buffer.from(String(bHex || ""), "utf8");
  if (!a.length || a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ✅ Validador robusto: acepta firma con stableStringify o JSON.stringify
function verifyHubSignature(reqBody: any, signatureHex: string, secret: string) {
  if (!signatureHex || !secret) return false;

  const expectedStable = bothubHmacStable(reqBody, secret);
  if (timingSafeEqualHex(signatureHex, expectedStable)) return true;

  const expectedJson = bothubHmacJson(reqBody, secret);
  if (timingSafeEqualHex(signatureHex, expectedJson)) return true;

  return false;
}

async function bothubReportMessage(payload: any) {
  // NO rompe tu bot si no está configurado
  if (!BOTHUB_WEBHOOK_URL || !BOTHUB_WEBHOOK_SECRET) return;

  try {
    const sig = bothubHmacStable(payload, BOTHUB_WEBHOOK_SECRET);
    await axios.post(BOTHUB_WEBHOOK_URL, payload, {
      headers: {
        "Content-Type": "application/json",
        "X-HUB-SIGNATURE": sig,
      },
      timeout: BOTHUB_TIMEOUT_MS,
    });
  } catch (e: any) {
    // silencioso para no tumbar el bot
    console.error("Bothub report failed:", e?.response?.data || e?.message || e);
  }
}

// ✅ NEW: meta para audio/ubicación/attachments (para que en Hub se vea TODO)
function extractInboundMeta(msg: any) {
  if (!msg) return {};

  // Audio
  if (msg?.type === "audio") {
    return {
      kind: "AUDIO",
      mediaId: msg?.audio?.id,
      mimeType: msg?.audio?.mime_type,
      voice: msg?.audio?.voice,
    };
  }

  // Location
  if (msg?.type === "location") {
    return {
      kind: "LOCATION",
      latitude: msg?.location?.latitude,
      longitude: msg?.location?.longitude,
      name: msg?.location?.name,
      address: msg?.location?.address,
    };
  }

  // Image / video / document / sticker
  if (msg?.type === "image")
    return {
      kind: "IMAGE",
      mediaId: msg?.image?.id,
      mimeType: msg?.image?.mime_type,
      caption: msg?.image?.caption,
    };
  if (msg?.type === "video")
    return {
      kind: "VIDEO",
      mediaId: msg?.video?.id,
      mimeType: msg?.video?.mime_type,
      caption: msg?.video?.caption,
    };
  if (msg?.type === "document")
    return {
      kind: "DOCUMENT",
      mediaId: msg?.document?.id,
      mimeType: msg?.document?.mime_type,
      filename: msg?.document?.filename,
    };
  if (msg?.type === "sticker") return { kind: "STICKER", mediaId: msg?.sticker?.id, mimeType: msg?.sticker?.mime_type };

  // Contacts / reaction
  if (msg?.type === "contacts") return { kind: "CONTACTS", count: msg?.contacts?.length || 0 };
  if (msg?.type === "reaction")
    return { kind: "REACTION", emoji: msg?.reaction?.emoji, messageId: msg?.reaction?.message_id };

  return { kind: msg?.type ? String(msg.type).toUpperCase() : "UNKNOWN" };
}

// =====================================================
// Express (raw body needed for signature verification)
// =====================================================
const app = express();
app.use(
  express.json({
    verify: (req: any, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// =====================================================
// In-memory sessions (MVP). In prod: Redis/DB
// =====================================================
const sessions = new Map<string, any>();

function getSession(userId: string) {
  if (!sessions.has(userId)) {
    sessions.set(userId, {
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      state: "idle",

      // lead fields
      goal: null, // bot | demo | human
      botType: null,
      sector: null,
      objective: null,
      channels: null, // ✅ se mantiene, pero se setea a WhatsApp automáticamente
      volume: null,
      urgency: null,
      name: null,
      business: null,
      city: null,
      link: null,
      notes: null,

      // meta referral (ads)
      referral: null,

      // conversational
      greeted: false,
      lastPrompt: "",
      messages: [], // short memory for AI
    });
  }
  const s = sessions.get(userId);
  s.lastSeenAt = Date.now();
  return s;
}

// Optional: cleanup old sessions every hour
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions.entries()) {
    if (now - (s.lastSeenAt || now) > 1000 * 60 * 60 * 24) {
      sessions.delete(k);
    }
  }
}, 1000 * 60 * 60);

// =====================================================
// Helpers
// =====================================================
function assertEnv() {
  const required = ["WA_TOKEN", "PHONE_NUMBER_ID", "VERIFY_TOKEN", "OPENAI_API_KEY"];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    console.warn("⚠️ Missing ENV:", missing.join(", "));
  }

  // ✅ avisos útiles para Bothub (sin romper)
  if (!BOTHUB_WEBHOOK_URL) console.warn("⚠️ Missing ENV: BOTHUB_WEBHOOK_URL (Hub won't receive messages)");
  if (!BOTHUB_WEBHOOK_SECRET) console.warn("⚠️ Missing ENV: BOTHUB_WEBHOOK_SECRET (Hub signature will fail)");
}
assertEnv();

function normalizeText(t: any) {
  return (t || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .replace(/\s+/g, " ")
    .trim();
}

function verifyMetaSignature(req: any) {
  // Optional: if META_APP_SECRET not set, skip verification
  if (!META_APP_SECRET) return true;

  const signature = req.get("X-Hub-Signature-256");
  if (!signature) return false;

  const expected =
    "sha256=" +
    crypto
      .createHmac("sha256", META_APP_SECRET)
      .update(req.rawBody || Buffer.from(""))
      .digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

function isGreeting(tNorm: string) {
  const t = tNorm || "";
  const greetings = ["hola", "buenas", "buenos dias", "buen dia", "buenas tardes", "buenas noches", "saludos", "hey", "hi"];
  const only =
    greetings.some((g) => t === g || t.startsWith(g + " ")) ||
    /^(hola+|buenas+|saludos+)\b/.test(t);

  const hasIntent =
    t.includes("precio") ||
    t.includes("cotiz") ||
    t.includes("demo") ||
    t.includes("llamada") ||
    t.includes("bot") ||
    t.includes("whatsapp") ||
    t.includes("automat") ||
    t.includes("cita");

  return only && !hasIntent && t.length <= 40;
}

function isHumanRequest(tNorm: string) {
  const t = tNorm || "";
  return ["humano", "asesor", "persona", "agente", "hablar contigo", "hablar con alguien", "llamar", "telefono", "teléfono", "llamada"].some(
    (k) => t.includes(k)
  );
}

function isPricingIntent(tNorm: string) {
  const t = tNorm || "";
  return ["precio", "cuanto cuesta", "cuánto cuesta", "costo", "inversion", "inversión", "cotizacion", "cotización", "tarifa", "planes"].some(
    (k) => t.includes(k)
  );
}

function isDemoIntent(tNorm: string) {
  const t = tNorm || "";
  return ["demo", "reunion", "reunión", "agendar", "cita", "llamada"].some((k) => t.includes(k));
}

function safeText(x: any, max = 400) {
  const s = (x || "").toString().trim();
  return s.length > max ? s.slice(0, max) + "…" : s;
}

function digitsOnly(s: any) {
  return (s || "").toString().replace(/[^\d]/g, "");
}

// =====================================================
// WhatsApp Senders
// ✅ NO TOCA TU LÓGICA: solo reporta OUTBOUND al Hub
// =====================================================
async function waSendText(to: any, body: any) {
  const url = `https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`;
  await axios.post(
    url,
    {
      messaging_product: "whatsapp",
      to,
      type: "text",
      text: { body },
    },
    { headers: { Authorization: `Bearer ${WA_TOKEN}` } }
  );

  // ✅ Reportar al Hub (OUTBOUND)
  await bothubReportMessage({
    direction: "OUTBOUND",
    to: String(to),
    body: String(body),
    source: "BOT",
    kind: "TEXT",
  });
}

async function waSendButtons(to: any, headerText: any, bodyText: any, buttons: any[]) {
  // buttons: [{id,title}] max 3
  const url = `https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`;
  await axios.post(
    url,
    {
      messaging_product: "whatsapp",
      to,
      type: "interactive",
      interactive: {
        type: "button",
        header: headerText ? { type: "text", text: headerText } : undefined,
        body: { text: bodyText },
        action: {
          buttons: buttons.slice(0, 3).map((b) => ({
            type: "reply",
            reply: { id: b.id, title: b.title },
          })),
        },
      },
    },
    { headers: { Authorization: `Bearer ${WA_TOKEN}` } }
  );

  // ✅ Reportar al Hub (OUTBOUND) - representación de UI como texto
  const rendered =
    `${headerText ? `*${headerText}*\n` : ""}${bodyText}\n\n` +
    buttons.slice(0, 3).map((b) => `• [${b.id}] ${b.title}`).join("\n");

  await bothubReportMessage({
    direction: "OUTBOUND",
    to: String(to),
    body: rendered,
    source: "BOT",
    kind: "BUTTONS",
    meta: { headerText, bodyText, buttons: buttons.slice(0, 3) },
  });
}

async function waSendList(to: any, headerText: any, bodyText: any, buttonText: any, sectionTitle: any, rows: any[]) {
  // rows: [{id,title,description?}]
  const url = `https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`;

  // ✅ FIX: WhatsApp limita row.title a 24 caracteres
  const clampTitle = (s: any) => {
    const t = (s || "").toString().trim();
    return t.length > 24 ? t.slice(0, 24) : t;
  };

  const finalRows = rows.map((r) => ({
    id: r.id,
    title: clampTitle(r.title),
    description: r.description || "",
  }));

  await axios.post(
    url,
    {
      messaging_product: "whatsapp",
      to,
      type: "interactive",
      interactive: {
        type: "list",
        header: headerText ? { type: "text", text: headerText } : undefined,
        body: { text: bodyText },
        action: {
          button: buttonText || "Ver opciones",
          sections: [
            {
              title: sectionTitle || "Opciones",
              rows: finalRows,
            },
          ],
        },
      },
    },
    { headers: { Authorization: `Bearer ${WA_TOKEN}` } }
  );

  // ✅ Reportar al Hub (OUTBOUND)
  const rendered =
    `${headerText ? `*${headerText}*\n` : ""}${bodyText}\n\n` +
    `(${buttonText || "Ver opciones"} · ${sectionTitle || "Opciones"})\n` +
    finalRows.map((r) => `• [${r.id}] ${r.title}${r.description ? ` — ${r.description}` : ""}`).join("\n");

  await bothubReportMessage({
    direction: "OUTBOUND",
    to: String(to),
    body: rendered,
    source: "BOT",
    kind: "LIST",
    meta: { headerText, bodyText, buttonText, sectionTitle, rows: finalRows },
  });
}

// =====================================================
// Flow Copy
// =====================================================
function welcomeText() {
  // ✅ Mantiene tu bienvenida, pero el flow será de 3 preguntas
  return `👋 ¡Hola! Soy el asistente de *${BRAND_NAME}*.\nTe hago 3 preguntas y te recomiendo el bot ideal ✅\n\n¿Qué deseas hacer hoy?`;
}

function antiRaroText() {
  return `Totalmente válido 😄\nPara ayudarte rápido, elige una opción y seguimos.\n\n¿Quieres un bot o deseas agendar una demo?`;
}

function pricingInfoText() {
  return `💡 Los bots se cotizan según funciones e integraciones.\n\nTenemos 3 niveles:\n• *Starter:* menú + captura de datos\n• *Pro:* ventas/citas + seguimiento\n• *Premium:* IA + integraciones (Sheets/CRM) + automatizaciones\n\n¿Quieres que te recomiende el mejor para tu negocio?`;
}

function doneCustomerText() {
  return `✅ Perfecto, ya tengo lo necesario.\n\nEn breve te enviamos una recomendación y próximos pasos.\nSi deseas hablar con un asesor, escribe *Humano* en este chat.`;
}

// =====================================================
// Lead Summary + Handoff
// =====================================================
function buildLeadSummary(session: any, userPhone: any) {
  const lines: string[] = [];
  lines.push(`📩 *Nuevo lead Tekko*`);
  lines.push(`📞 WhatsApp: ${userPhone}`);
  if (session.name) lines.push(`👤 Nombre: ${session.name}`);
  if (session.business) lines.push(`🏢 Negocio: ${session.business}`);
  if (session.city) lines.push(`📍 Ciudad: ${session.city}`);
  if (session.sector) lines.push(`🏷️ Sector: ${session.sector}`);
  if (session.goal) lines.push(`🎯 Intención: ${session.goal}`);
  if (session.botType) lines.push(`🤖 Tipo de bot: ${session.botType}`);
  if (session.objective) lines.push(`✅ Objetivo: ${session.objective}`);
  if (session.channels) lines.push(`📲 Canales: ${session.channels}`);
  if (session.volume) lines.push(`💬 Mensajes/día: ${session.volume}`);
  if (session.urgency) lines.push(`⏳ Urgencia: ${session.urgency}`);
  if (session.link) lines.push(`🔗 Link: ${session.link}`);
  if (session.notes) lines.push(`📝 Notas: ${session.notes}`);

  if (session.referral) {
    lines.push(`📣 *Ref:* ${JSON.stringify(session.referral).slice(0, 300)}…`);
  }

  return lines.join("\n");
}

async function notifyAdmin(session: any, userPhone: any) {
  if (!ADMIN_PHONE) return;
  const summary = buildLeadSummary(session, userPhone);
  try {
    await waSendText(ADMIN_PHONE, summary);
  } catch (e: any) {
    console.error("Admin notify failed:", e?.response?.data || e?.message || e);
  }
}

// =====================================================
// OpenAI (ChatGPT) - controlled sales assistant
// =====================================================
async function callOpenAI({ userId, userPhone, userText, session }: any) {
  // keep short memory
  session.messages.push({ role: "user", content: safeText(userText, 600) });
  session.messages = session.messages.slice(-10);

  const system = {
    role: "system",
    content: `
Eres un asistente de ventas por WhatsApp de ${BRAND_NAME}.
Objetivo: ayudar al cliente a entender bots/automatización, responder dudas y mantenerlo en el flujo.
Reglas:
- Responde corto, claro y práctico.
- NO inventes precios exactos. Si preguntan precio, explica que depende y ofrece niveles (Starter/Pro/Premium) y pide datos mínimos.
- El flujo tiene SOLO 3 preguntas clave: (1) tipo de bot (2) sector (3) objetivo.
- Si el usuario se va por otro tema, responde con IA y luego recuérdale completar esas 3 preguntas con opciones.
- Si el usuario pide hablar con humano, confirma y resume.
- Idioma: español (tono friendly, profesional).
Contexto actual del lead (puede estar incompleto):
${JSON.stringify(
  {
    goal: session.goal,
    botType: session.botType,
    sector: session.sector,
    objective: session.objective,
    channels: session.channels,
    volume: session.volume,
    urgency: session.urgency,
    name: session.name,
    business: session.business,
    city: session.city,
  },
  null,
  2
)}
`,
  };

  const payload = {
    model: OPENAI_MODEL,
    temperature: 0.3,
    messages: [system, ...session.messages],
  };

  const resp = await axios.post("https://api.openai.com/v1/chat/completions", payload, {
    headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
  });

  const text = resp.data?.choices?.[0]?.message?.content?.trim() || "";
  session.messages.push({ role: "assistant", content: safeText(text, 900) });
  session.messages = session.messages.slice(-10);
  return text;
}

// =====================================================
// Incoming parsing (text + interactive + audio/location/etc)
// =====================================================
function extractIncomingText(msg: any) {
  if (!msg) return "";

  // Texto normal
  if (msg?.text?.body) return msg.text.body;

  // Botones/listas
  if (msg?.type === "interactive" && msg?.interactive?.button_reply) {
    const br = msg.interactive.button_reply;
    return br.id || br.title || "";
  }
  if (msg?.type === "interactive" && msg?.interactive?.list_reply) {
    const lr = msg.interactive.list_reply;
    return lr.id || lr.title || "";
  }

  // Nota de voz / audio
  if (msg?.type === "audio" && msg?.audio?.id) {
    return "[AUDIO]";
  }

  // Ubicación
  if (msg?.type === "location" && msg?.location) {
    const { latitude, longitude, name, address } = msg.location;
    return `📍 Ubicación: ${name || ""} ${address || ""} (${latitude}, ${longitude})`.trim();
  }

  // Imagen / video / documento / sticker
  if (msg?.type === "image" && msg?.image?.id) return "[IMAGE]";
  if (msg?.type === "video" && msg?.video?.id) return "[VIDEO]";
  if (msg?.type === "document" && msg?.document?.id) return "[DOCUMENT]";
  if (msg?.type === "sticker" && msg?.sticker?.id) return "[STICKER]";

  // Contacto compartido
  if (msg?.type === "contacts" && msg?.contacts?.length) return "[CONTACTS]";

  // Reacción
  if (msg?.type === "reaction" && msg?.reaction) return `[REACTION] ${msg.reaction.emoji || ""}`.trim();

  // Fallback
  return `[${(msg?.type || "UNKNOWN").toUpperCase()}]`;
}

function extractReferral(msg: any) {
  // Meta can send referral objects on some entrypoints
  // Keep raw to store for admin context
  return msg?.referral || null;
}

// =====================================================
// Menus
// =====================================================
async function sendMainMenu(to: any) {
  // ✅ CAMBIO: eliminar "Info / precios" del menú inicial
  await waSendButtons(to, BRAND_NAME, welcomeText(), [
    { id: "goal_bot", title: "🤖 Quiero un bot" },
    { id: "goal_demo", title: "🗓️ Agendar demo" },
    { id: "goal_human", title: "📞 Hablar con asesor" },
  ]);
  // "humano" as text option (por si no toca botón)
  await waSendText(to, `Si prefieres, escribe: *Humano* para hablar con un asesor.`);
}

async function sendBotTypes(to: any) {
  await waSendList(
    to,
    "Tipos de bot",
    "Perfecto ✅ (1/3) ¿Para qué lo necesitas principalmente?",
    "Ver tipos",
    "Opciones",
    [
      { id: "bot_sales", title: "🛒 Bot de Ventas", description: "Catálogo, pedidos, carrito, pagos" },
      { id: "bot_appointments", title: "📅 Bot de Citas/Reservas", description: "Agenda automática, recordatorios" },
      { id: "bot_support", title: "🧾 Bot de Soporte", description: "FAQ, seguimiento, reclamos" },
      { id: "bot_delivery", title: "🏪 Bot Delivery/Rest.", description: "Menú, pedidos, ubicación" },
      { id: "bot_services", title: "🧑‍💼 Bot para Servicios", description: "Cotizaciones, formularios, leads" },
      { id: "bot_ai", title: "🧠 Bot con IA", description: "Responde como asesor con tu info" },
      { id: "bot_automations", title: "🔁 Automatizaciones", description: "Sheets/CRM/Notion/Calendar" },
      { id: "bot_recommend", title: "❓ No sé / Recom.", description: "Te hago 3 preguntas y te digo" },
    ]
  );
}

async function sendSectorMenu(to: any) {
  await waSendList(
    to,
    "Sector",
    "Listo ✅ (2/3) ¿A qué se dedica tu negocio?",
    "Elegir",
    "Sectores",
    [
      { id: "sector_restaurante", title: "Restaurante / Delivery" },
      { id: "sector_tienda", title: "Tienda / eCommerce" },
      { id: "sector_belleza", title: "Belleza / Spa / Salón" },
      { id: "sector_salud", title: "Salud / Clínica" },
      { id: "sector_inmobiliaria", title: "Inmobiliaria" },
      { id: "sector_servicios", title: "Servicios Profesionales" },
      { id: "sector_otro", title: "Otro" },
    ]
  );
}

async function sendObjectiveMenu(to: any) {
  await waSendList(
    to,
    "Objetivo",
    "Última ✅ (3/3) ¿Qué quieres lograr con el bot?",
    "Elegir",
    "Objetivos",
    [
      { id: "obj_vender", title: "Vender más" },
      { id: "obj_ahorrar", title: "Ahorrar tiempo" },
      { id: "obj_responder", title: "Responder más rápido" },
      { id: "obj_agendar", title: "Agendar citas / reservas" },
      { id: "obj_soporte", title: "Soporte / seguimiento" },
      { id: "obj_otro", title: "Otro" },
    ]
  );
}

// ✅ Solo WhatsApp (sin Instagram/Facebook como canal del bot)
async function sendChannelsMenu(to: any) {
  await waSendList(to, "Canal", "Este bot es para WhatsApp ✅", "Elegir", "Canal", [{ id: "ch_whatsapp", title: "WhatsApp" }]);
}

async function sendVolumeMenu(to: any) {
  await waSendList(
    to,
    "Volumen",
    "Aproximadamente, ¿cuántos mensajes recibes al día?",
    "Elegir",
    "Rangos",
    [
      { id: "vol_0_20", title: "0–20" },
      { id: "vol_20_50", title: "20–50" },
      { id: "vol_50_100", title: "50–100" },
      { id: "vol_100_plus", title: "100+" },
    ]
  );
}

async function sendUrgencyMenu(to: any) {
  await waSendList(
    to,
    "Urgencia",
    "¿Para cuándo lo necesitas?",
    "Elegir",
    "Tiempos",
    [
      { id: "urg_week", title: "Esta semana" },
      { id: "urg_2w", title: "En 2 semanas" },
      { id: "urg_month", title: "Este mes" },
      { id: "urg_eval", title: "Solo estoy evaluando" },
    ]
  );
}

// (Se mantiene por compatibilidad, pero YA NO se envía automáticamente)
async function sendCloseMenu(to: any) {
  await waSendButtons(to, "Siguiente paso", "¿Cómo quieres continuar?", [
    { id: "close_demo", title: "🗓️ Agendar demo" },
    { id: "close_quote", title: "💬 Cotización" },
    { id: "close_human", title: "📞 Hablar humano" },
  ]);
}

// =====================================================
// State machine
// =====================================================
function mapIdToLabel(id: any) {
  const m: Record<string, string> = {
    goal_bot: "Quiero un bot",
    goal_prices: "Info / precios", // ✅ se mantiene por compatibilidad, pero ya no está en el menú
    goal_demo: "Agendar demo",
    goal_human: "Hablar con humano",

    bot_sales: "Bot de Ventas",
    bot_appointments: "Bot de Citas/Reservas",
    bot_support: "Bot de Soporte",
    bot_delivery: "Bot Delivery/Restaurante",
    bot_services: "Bot para Servicios",
    bot_ai: "Bot con IA",
    bot_automations: "Automatizaciones",
    bot_recommend: "No sé / Recomiéndame",

    sector_restaurante: "Restaurante / Delivery",
    sector_tienda: "Tienda / eCommerce",
    sector_belleza: "Belleza / Spa / Salón",
    sector_salud: "Salud / Clínica",
    sector_inmobiliaria: "Inmobiliaria",
    sector_servicios: "Servicios Profesionales",
    sector_otro: "Otro",

    obj_vender: "Vender más",
    obj_ahorrar: "Ahorrar tiempo",
    obj_responder: "Responder más rápido",
    obj_agendar: "Agendar citas / reservas",
    obj_soporte: "Soporte / seguimiento",
    obj_otro: "Otro",

    ch_whatsapp: "WhatsApp",

    vol_0_20: "0–20",
    vol_20_50: "20–50",
    vol_50_100: "50–100",
    vol_100_plus: "100+",

    urg_week: "Esta semana",
    urg_2w: "En 2 semanas",
    urg_month: "Este mes",
    urg_eval: "Solo evaluando",
  };
  return m[id] || null;
}

// ✅ NEW: recordatorio inteligente del flujo (3 preguntas)
async function remind3Questions(to: any, session: any) {
  const missing: string[] = [];
  if (!session.botType) missing.push("tipo de bot");
  if (!session.sector) missing.push("sector");
  if (!session.objective) missing.push("objetivo");

  if (!missing.length) return;

  const nice =
    missing.length === 1 ? missing[0] : missing.length === 2 ? `${missing[0]} y ${missing[1]}` : `${missing[0]}, ${missing[1]} y ${missing[2]}`;

  await waSendText(to, `Para avanzar rápido ✅ solo me falta: *${nice}*.\nElige una opción aquí 👇`);
}

async function stepAskNext(to: any, session: any) {
  // Decide next missing field based on flow
  if (!session.goal) {
    session.state = "idle";
    await sendMainMenu(to);
    return;
  }

  // ✅ CAMBIO: ya no guiamos por "Info / precios" como menú (se mantiene compat si el usuario lo escribe)
  if (session.goal === "Info / precios") {
    // Mantener compat: responder con info general y empujar a las 3 preguntas
    session.state = "collect_bot_type";
    await waSendText(to, pricingInfoText());
    await sendBotTypes(to);
    return;
  }

  // ✅ CAMBIO: tanto "Quiero un bot" como "Agendar demo" usan las MISMAS 3 preguntas
  if (session.goal === "Agendar demo") {
    if (!session.botType) {
      session.state = "collect_bot_type";
      await waSendText(to, `Perfecto ✅ Empecemos rápido con 3 preguntas.`);
      await sendBotTypes(to);
      return;
    }
  }

  // goal: want bot / demo
  if (!session.botType) {
    session.state = "collect_bot_type";
    await sendBotTypes(to);
    return;
  }

  if (!session.sector) {
    session.state = "collect_sector";
    await sendSectorMenu(to);
    return;
  }

  if (!session.objective) {
    session.state = "collect_objective";
    await sendObjectiveMenu(to);
    return;
  }

  // ✅ SOLO WhatsApp: no preguntar canal, se setea automático
  if (!session.channels) {
    session.channels = "WhatsApp";
  }

  // ✅ CAMBIO CLAVE: el flujo termina aquí (3 preguntas) — lo demás se mantiene en el código pero ya no es requerido
  session.state = "done";
  await waSendText(to, doneCustomerText());

  // notify admin con lo que ya tenemos (sin obligar a más preguntas)
  await notifyAdmin(session, to);
}

async function handleCloseChoice(to: any, session: any, choiceId: any) {
  if (choiceId === "close_demo") {
    session.goal = session.goal || "Agendar demo";
    await waSendText(
      to,
      `🗓️ Listo ✅\nEscríbeme *2 horarios* que te queden bien (Ej: Hoy 5pm o Mañana 11am) y un asesor confirma contigo.`
    );
    await notifyAdmin({ ...session, notes: (session.notes || "") + " | Cliente pidió DEMO" }, to);
    return;
  }

  if (choiceId === "close_quote") {
    await waSendText(
      to,
      `💬 Perfecto ✅\nCon lo que me diste, te preparo una propuesta.\nSi quieres agregar algún detalle, escríbelo ahora (Ej: “quiero pagos, catálogo, Google Sheets, IA”).`
    );
    await notifyAdmin({ ...session, notes: (session.notes || "") + " | Cliente pidió COTIZACIÓN" }, to);
    return;
  }

  if (choiceId === "close_human") {
    await waSendText(to, `📞 Claro ✅ Te paso con un asesor ahora.\nMientras tanto, dime cualquier detalle extra que debamos saber.`);
    await notifyAdmin({ ...session, notes: (session.notes || "") + " | Cliente pidió HUMANO" }, to);
    return;
  }
}

// =====================================================
// ✅ NEW: endpoint para recibir mensaje del AGENTE desde BotHub
// POST /agent_message
// body: { conversationId, waTo, text, agentUserId }
// header: X-HUB-SIGNATURE (HMAC)
// =====================================================
app.post("/agent_message", async (req: any, res: any) => {
  try {
    if (!BOTHUB_WEBHOOK_SECRET) {
      return res.status(400).json({ error: "BOTHUB_WEBHOOK_SECRET not configured" });
    }

    const signature = getHubSignature(req);

    // ✅ FIX REAL: aceptar firma stableStringify O JSON.stringify
    const okSig = verifyHubSignature(req.body, signature, BOTHUB_WEBHOOK_SECRET);

    if (!signature || !okSig) {
      // log corto para debug (no imprime secretos)
      console.warn("[agent_message] Invalid signature", {
        hasSignature: Boolean(signature),
        sigLen: signature ? String(signature).length : 0,
      });
      return res.status(401).json({ error: "Invalid signature" });
    }

    const { waTo, text } = req.body || {};
    if (!waTo || !String(waTo).trim()) return res.status(400).json({ error: "waTo is required" });
    if (!text || !String(text).trim()) return res.status(400).json({ error: "text is required" });

    // Enviar por WhatsApp como AGENTE (humano)
    // ⚠️ Nota: waSendText reporta al Hub como source BOT (por tu implementación).
    // Para no duplicar y para mantener tu lógica, lo dejamos igual.
    // Igual reportamos luego el OUTBOUND como AGENT para BotHub.
    await waSendText(String(waTo), String(text));

    // Reportar al Hub como OUTBOUND (source AGENT)
    await bothubReportMessage({
      direction: "OUTBOUND",
      to: String(waTo),
      body: String(text),
      source: "AGENT",
      conversationId: req.body?.conversationId,
      agentUserId: req.body?.agentUserId,
      kind: "TEXT",
    });

    return res.json({ ok: true });
  } catch (e: any) {
    console.error("agent_message error:", e?.response?.data || e?.message || e);
    return res.status(500).json({ error: "Internal error" });
  }
});

// =====================================================
// Webhook verify
// =====================================================
app.get("/webhook", (req: any, res: any) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) return res.status(200).send(challenge);
  return res.sendStatus(403);
});

// =====================================================
// Webhook receive
// =====================================================
app.post("/webhook", async (req: any, res: any) => {
  try {
    if (!verifyMetaSignature(req)) return res.sendStatus(403);

    const entry = req.body.entry?.[0];
    const change = entry?.changes?.[0];
    const value = change?.value;

    const msg = value?.messages?.[0];
    if (!msg) return res.sendStatus(200);

    const from = msg.from;
    if (!from) return res.sendStatus(200);

    const session = getSession(from);

    // Save referral if any
    const referral = extractReferral(msg);
    if (referral && !session.referral) session.referral = referral;

    const raw = extractIncomingText(msg);
    const userText = (raw || "").trim();
    const tNorm = normalizeText(userText);

    if (!userText) return res.sendStatus(200);

    // ✅ NEW: Reportar INBOUND al Hub (texto + meta para audio/ubicación/attachments)
    const inboundMeta = extractInboundMeta(msg);
    await bothubReportMessage({
      direction: "INBOUND",
      from: String(from),
      body: String(userText),
      source: "WHATSAPP",
      waMessageId: msg?.id,
      name: value?.contacts?.[0]?.profile?.name,
      kind: inboundMeta?.kind || (msg?.type ? String(msg.type).toUpperCase() : "UNKNOWN"),
      meta: inboundMeta,
    });

    // Quick intents
    if (isHumanRequest(tNorm)) {
      session.goal = session.goal || "Hablar con humano";

      let extraContact = "";
      if (ADMIN_PHONE) {
        const d = digitsOnly(ADMIN_PHONE);
        extraContact = `\n\n📲 Puedes escribirnos aquí: https://wa.me/${d}`;
      }

      await waSendText(from, `Claro ✅ Te paso con un asesor.\nDime en una línea qué necesitas (tipo de bot y negocio).${extraContact}`);
      await notifyAdmin({ ...session, notes: (session.notes || "") + " | Pidió HUMANO (keyword)" }, from);
      return res.sendStatus(200);
    }

    // Anti-raro phrase handling (se mantiene, pero ahora también dejamos que IA responda si hace falta)
    if (tNorm.includes("como vendes") || tNorm.includes("y tu no tienes") || tNorm.includes("raro") || tNorm.includes("no tienes uno")) {
      // ✅ CAMBIO: IA responde y luego recordamos las 3 preguntas
      const aiReply = await callOpenAI({
        userId: from,
        userPhone: from,
        userText,
        session,
      });

      if (aiReply) await waSendText(from, aiReply);
      await waSendText(from, antiRaroText());

      if (!session.goal) session.goal = "Quiero un bot";
      session.state = "collect_bot_type";
      await remind3Questions(from, session);
      await sendBotTypes(from);
      return res.sendStatus(200);
    }

    // If first time and greeting simple -> show menu once
    if (!session.greeted && isGreeting(tNorm)) {
      session.greeted = true;
      await sendMainMenu(from);
      return res.sendStatus(200);
    }
    if (!session.greeted) session.greeted = true;

    // Interpret menu button/list IDs
    const label = mapIdToLabel(userText);

    // Main menu choices
    if (userText === "goal_bot") {
      session.goal = "Quiero un bot";
      await waSendText(from, `Perfecto ✅ Empecemos rápido con 3 preguntas.`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }
    if (userText === "goal_prices") {
      // compat: si alguien lo manda, respondemos pero seguimos con 3 preguntas
      session.goal = "Info / precios";
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }
    if (userText === "goal_demo") {
      session.goal = "Agendar demo";
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }
    if (userText === "goal_human") {
      session.goal = "Hablar con humano";
      let extraContact = "";
      if (ADMIN_PHONE) {
        const d = digitsOnly(ADMIN_PHONE);
        extraContact = `\n\n📲 Puedes escribirnos aquí: https://wa.me/${d}`;
      }
      await waSendText(from, `Claro ✅ Te paso con un asesor.\nDime en una línea qué necesitas (tipo de bot y negocio).${extraContact}`);
      await notifyAdmin({ ...session, notes: (session.notes || "") + " | Pidió HUMANO (menu)" }, from);
      return res.sendStatus(200);
    }

    // Close choices
    if (["close_demo", "close_quote", "close_human"].includes(userText)) {
      await handleCloseChoice(from, session, userText);
      return res.sendStatus(200);
    }

    // If user typed "menu"
    if (tNorm.includes("menu") || tNorm.includes("menú") || tNorm.includes("empezar") || tNorm === "inicio") {
      await sendMainMenu(from);
      return res.sendStatus(200);
    }

    // If user asks pricing at any time
    if (isPricingIntent(tNorm) && session.state !== "done") {
      // ✅ CAMBIO: la IA responde y luego empujamos a las 3 preguntas (sin agregar más preguntas)
      session.goal = session.goal || "Quiero un bot";
      const aiReply = await callOpenAI({
        userId: from,
        userPhone: from,
        userText,
        session,
      });
      if (aiReply) await waSendText(from, aiReply);

      // seguimos el flujo 3 preguntas
      await remind3Questions(from, session);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    // If user asks demo at any time
    if (isDemoIntent(tNorm) && session.state !== "done") {
      session.goal = session.goal || "Agendar demo";
      await waSendText(from, `Perfecto ✅ Solo 3 preguntas rápidas y coordinamos.`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    // Handle structured flow states
    if (session.state === "collect_bot_type") {
      if ((label && label.startsWith("Bot")) || label === "Automatizaciones" || label === "No sé / Recomiéndame") {
        session.botType = label;
        await waSendText(from, `Genial ✅`);
        await stepAskNext(from, session);
        return res.sendStatus(200);
      }

      // ✅ CAMBIO: si escribe algo raro, IA responde y lo re-encarrilamos (sin romper compat: aún aceptamos texto)
      if (tNorm.length >= 2) {
        // aceptar texto libre como botType (compat)
        session.botType = safeText(userText, 80);
        await waSendText(from, `Perfecto ✅`);
        await stepAskNext(from, session);
        return res.sendStatus(200);
      }
    }

    if (session.state === "collect_sector") {
      if (label) session.sector = label;
      else session.sector = safeText(userText, 80);
      await waSendText(from, `✅`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    if (session.state === "collect_objective") {
      if (label) session.objective = label;
      else session.objective = safeText(userText, 120);
      await waSendText(from, `✅`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    if (!session.channels) session.channels = "WhatsApp";

    // ---- Se mantiene tu lógica existente (ya no es requerida por el flujo de 3 preguntas) ----
    if (session.state === "collect_volume") {
      if (label) session.volume = label;
      else session.volume = safeText(userText, 60);
      await waSendText(from, `✅`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    if (session.state === "collect_urgency") {
      if (label) session.urgency = label;
      else session.urgency = safeText(userText, 60);
      await waSendText(from, `✅`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    if (session.state === "collect_name") {
      if (tNorm.length < 3) {
        await waSendText(from, `Por favor envíame tu *nombre y apellido* 🙂`);
        return res.sendStatus(200);
      }
      session.name = safeText(userText, 80);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    if (session.state === "collect_business") {
      if (tNorm.length < 2) {
        await waSendText(from, `¿Cómo se llama tu negocio?`);
        return res.sendStatus(200);
      }
      session.business = safeText(userText, 100);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    if (session.state === "collect_city") {
      session.city = safeText(userText, 80);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    if (session.state === "collect_link") {
      if (tNorm.includes("no tengo") || tNorm === "no") session.link = "No tiene";
      else session.link = safeText(userText, 200);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }
    // ---- fin compat ----

    if (session.state === "done") {
      if (tNorm.length > 2) {
        session.notes = safeText((session.notes ? session.notes + " | " : "") + userText, 400);
        await waSendText(from, `Perfecto ✅ Quedó anotado.\nSi deseas hablar con un asesor, escribe *Humano*.`);
        await notifyAdmin({ ...session, notes: (session.notes || "") + " | Mensaje post-done" }, from);
        return res.sendStatus(200);
      }
    }

    // If none matched and still no goal -> show menu
    if (!session.goal) {
      await sendMainMenu(from);
      return res.sendStatus(200);
    }

    // ✅ CAMBIO: si el usuario escribe "algo raro", la IA responde y luego lo re-encarrilamos a las 3 preguntas
    const aiReply = await callOpenAI({
      userId: from,
      userPhone: from,
      userText,
      session,
    });

    if (aiReply) {
      await waSendText(from, aiReply);
      // ✅ Nota: OUTBOUND al Hub ya se reporta dentro de waSendText()
    }

    if (!session.channels) session.channels = "WhatsApp";

    // ✅ CAMBIO CLAVE: solo 3 campos requeridos para terminar
    const needsMore =
      !session.botType ||
      !session.sector ||
      !session.objective;

    if (needsMore) {
      await remind3Questions(from, session);
      // re-mostrar el menú correcto según lo que falta (sin añadir preguntas extras)
      if (!session.botType) {
        session.state = "collect_bot_type";
        await sendBotTypes(from);
      } else if (!session.sector) {
        session.state = "collect_sector";
        await sendSectorMenu(from);
      } else if (!session.objective) {
        session.state = "collect_objective";
        await sendObjectiveMenu(from);
      } else {
        await stepAskNext(from, session);
      }
    } else if (session.state !== "done") {
      session.state = "done";
      await waSendText(from, doneCustomerText());
      await notifyAdmin(session, from);
    }

    return res.sendStatus(200);
  } catch (e: any) {
    console.error("Webhook error:", e?.response?.data || e?.message || e);
    return res.sendStatus(200);
  }
});

// Health
app.get("/", (_req: any, res: any) => res.send("OK"));

// Start
app.listen(PORT, () => console.log(`✅ ${BRAND_NAME} bot running on :${PORT}`));
