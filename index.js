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
const ADMIN_PHONE = process.env.ADMIN_PHONE || ""; // e.g. 1809XXXXXXX (E.164 digits only preferred)
const DEFAULT_COUNTRY_HINT = process.env.DEFAULT_COUNTRY_HINT || "República Dominicana";

// =====================================================
// Express (raw body needed for signature verification)
// =====================================================
const app = express();
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// =====================================================
// In-memory sessions (MVP). In prod: Redis/DB
// =====================================================
const sessions = new Map();

function getSession(userId) {
  if (!sessions.has(userId)) {
    sessions.set(userId, {
      createdAt: Date.now(),
      lastSeenAt: Date.now(),
      state: "idle",

      // lead fields
      goal: null, // bot | prices | demo | human
      botType: null,
      sector: null,
      objective: null,
      channels: null,
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
}
assertEnv();

function normalizeText(t) {
  return (t || "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "")
    .replace(/\s+/g, " ")
    .trim();
}

function verifyMetaSignature(req) {
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

function isGreeting(tNorm) {
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

function isHumanRequest(tNorm) {
  const t = tNorm || "";
  return ["humano", "asesor", "persona", "hablar contigo", "llamar", "telefono", "llamada"].some((k) => t.includes(k));
}

function isPricingIntent(tNorm) {
  const t = tNorm || "";
  return ["precio", "cuanto cuesta", "costo", "inversion", "cotizacion", "tarifa", "planes"].some((k) => t.includes(k));
}

function isDemoIntent(tNorm) {
  const t = tNorm || "";
  return ["demo", "reunion", "reunión", "agendar", "cita", "llamada"].some((k) => t.includes(k));
}

function safeText(x, max = 400) {
  const s = (x || "").toString().trim();
  return s.length > max ? s.slice(0, max) + "…" : s;
}

// =====================================================
// WhatsApp Senders
// =====================================================
async function waSendText(to, body) {
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
}

async function waSendButtons(to, headerText, bodyText, buttons) {
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
}

async function waSendList(to, headerText, bodyText, buttonText, sectionTitle, rows) {
  // rows: [{id,title,description?}]
  const url = `https://graph.facebook.com/v20.0/${PHONE_NUMBER_ID}/messages`;

  // ✅ FIX: WhatsApp limita row.title a 24 caracteres
  const clampTitle = (s) => {
    const t = (s || "").toString().trim();
    return t.length > 24 ? t.slice(0, 24) : t;
  };

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
              rows: rows.map((r) => ({
                id: r.id,
                title: clampTitle(r.title), // ✅ aquí el cambio
                description: r.description || "",
              })),
            },
          ],
        },
      },
    },
    { headers: { Authorization: `Bearer ${WA_TOKEN}` } }
  );
}

// =====================================================
// Flow Copy
// =====================================================
function welcomeText() {
  return `👋 ¡Hola! Soy el asistente de *${BRAND_NAME}*.\nTe ayudo a elegir el bot ideal para tu negocio en 1 minuto ✅\n\n¿Qué deseas hacer hoy?`;
}

function antiRaroText() {
  return `Totalmente válido 😄\nEste chat *es parte del bot de ${BRAND_NAME}* (lo usamos para filtrar y cotizar rápido).\n\nPara ayudarte: ¿quieres un bot de *ventas*, *citas* o *soporte*?`;
}

function pricingInfoText() {
  return `💡 Los bots se cotizan según funciones e integraciones.\n\nTenemos 3 niveles:\n• *Starter:* menú + captura de datos\n• *Pro:* ventas/citas + seguimiento\n• *Premium:* IA + integraciones (Sheets/CRM) + automatizaciones\n\n¿Quieres que te recomiende el mejor para tu negocio?`;
}

// =====================================================
// Lead Summary + Handoff
// =====================================================
function buildLeadSummary(session, userPhone) {
  const lines = [];
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

async function notifyAdmin(session, userPhone) {
  if (!ADMIN_PHONE) return;
  const summary = buildLeadSummary(session, userPhone);
  try {
    await waSendText(ADMIN_PHONE, summary);
  } catch (e) {
    console.error("Admin notify failed:", e?.response?.data || e?.message || e);
  }
}

// =====================================================
// OpenAI (ChatGPT) - controlled sales assistant
// =====================================================
async function callOpenAI({ userId, userPhone, userText, session }) {
  // keep short memory
  session.messages.push({ role: "user", content: safeText(userText, 600) });
  session.messages = session.messages.slice(-10);

  const system = {
    role: "system",
    content: `
Eres un asistente de ventas por WhatsApp de ${BRAND_NAME}.
Objetivo: ayudar al cliente a entender bots/automatización, hacer preguntas para calificar y llevarlo a demo/cotización.
Reglas:
- Responde corto, claro y práctico.
- NO inventes precios exactos. Si preguntan precio, explica que depende y ofrece rangos/niveles (Starter/Pro/Premium) y pide datos.
- Pide SOLO datos necesarios (sector, objetivo, canal, volumen, urgencia).
- Si el usuario pide hablar con humano, confirma y resume.
- No pidas información sensible.
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
// Incoming parsing (text + interactive)
// =====================================================
function extractIncomingText(msg) {
  if (!msg) return "";

  if (msg?.text?.body) return msg.text.body;

  if (msg?.type === "interactive" && msg?.interactive?.button_reply) {
    const br = msg.interactive.button_reply;
    return br.id || br.title || "";
  }

  if (msg?.type === "interactive" && msg?.interactive?.list_reply) {
    const lr = msg.interactive.list_reply;
    return lr.id || lr.title || "";
  }

  return "";
}

function extractReferral(msg) {
  // Meta can send referral objects on some entrypoints
  // Keep raw to store for admin context
  return msg?.referral || null;
}

// =====================================================
// Menus
// =====================================================
async function sendMainMenu(to) {
  await waSendButtons(to, BRAND_NAME, welcomeText(), [
    { id: "goal_bot", title: "🤖 Quiero un bot" },
    { id: "goal_prices", title: "💬 Info / precios" },
    { id: "goal_demo", title: "🗓️ Agendar demo" },
  ]);
  // "humano" as text option (because buttons max 3)
  await waSendText(to, `Si prefieres, escribe: *Humano* para hablar con un asesor.`);
}

async function sendBotTypes(to) {
  await waSendList(
    to,
    "Tipos de bot",
    "Perfecto ✅ ¿Para qué lo necesitas principalmente?",
    "Ver tipos",
    "Opciones",
    [
      { id: "bot_sales", title: "🛒 Bot de Ventas", description: "Catálogo, pedidos, carrito, pagos" },
      { id: "bot_appointments", title: "📅 Bot de Citas/Reservas", description: "Agenda automática, recordatorios" },
      { id: "bot_support", title: "🧾 Bot de Soporte", description: "FAQ, seguimiento, reclamos" },
      { id: "bot_delivery", title: "🏪 Bot Delivery/Restaurante", description: "Menú, pedidos, ubicación" },
      { id: "bot_services", title: "🧑‍💼 Bot para Servicios", description: "Cotizaciones, formularios, leads" },
      { id: "bot_ai", title: "🧠 Bot con IA", description: "Responde como asesor con tu info" },
      { id: "bot_automations", title: "🔁 Automatizaciones", description: "Sheets/CRM/Notion/Calendar" },
      { id: "bot_recommend", title: "❓ No sé / Recomiéndame", description: "Te hago 3 preguntas y te digo" },
    ]
  );
}

async function sendSectorMenu(to) {
  await waSendList(
    to,
    "Sector",
    "¿A qué se dedica tu negocio?",
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

async function sendObjectiveMenu(to) {
  await waSendList(
    to,
    "Objetivo",
    "¿Qué quieres lograr con el bot?",
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

async function sendChannelsMenu(to) {
  await waSendList(
    to,
    "Canales",
    "¿Dónde quieres el bot?",
    "Elegir",
    "Canales",
    [
      { id: "ch_whatsapp", title: "WhatsApp" },
      { id: "ch_instagram", title: "Instagram DM" },
      { id: "ch_facebook", title: "Facebook Messenger" },
      { id: "ch_all", title: "Todos" },
    ]
  );
}

async function sendVolumeMenu(to) {
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

async function sendUrgencyMenu(to) {
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

async function sendCloseMenu(to) {
  await waSendButtons(to, "Siguiente paso", "¿Cómo quieres continuar?", [
    { id: "close_demo", title: "🗓️ Agendar demo" },
    { id: "close_quote", title: "💬 Cotización por WhatsApp" },
    { id: "close_human", title: "📞 Hablar con humano" },
  ]);
}

// =====================================================
// State machine
// =====================================================
function mapIdToLabel(id) {
  const m = {
    goal_bot: "Quiero un bot",
    goal_prices: "Info / precios",
    goal_demo: "Agendar demo",

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
    ch_instagram: "Instagram DM",
    ch_facebook: "Facebook Messenger",
    ch_all: "Todos",

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

async function stepAskNext(to, session) {
  // Decide next missing field based on flow
  if (!session.goal) {
    session.state = "idle";
    await sendMainMenu(to);
    return;
  }

  if (session.goal === "Info / precios") {
    // keep them in funnel: ask to recommend
    session.state = "collect_bot_type";
    await waSendText(to, pricingInfoText());
    await sendBotTypes(to);
    return;
  }

  if (session.goal === "Agendar demo") {
    // ask basics then close with demo
    session.state = "collect_bot_type";
    await waSendText(to, `Perfecto ✅ Para preparar la demo, dime qué tipo de bot te interesa:`);
    await sendBotTypes(to);
    return;
  }

  // goal: want bot
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

  if (!session.channels) {
    session.state = "collect_channels";
    await sendChannelsMenu(to);
    return;
  }

  if (!session.volume) {
    session.state = "collect_volume";
    await sendVolumeMenu(to);
    return;
  }

  if (!session.urgency) {
    session.state = "collect_urgency";
    await sendUrgencyMenu(to);
    return;
  }

  // identity capture
  if (!session.name) {
    session.state = "collect_name";
    session.lastPrompt = `Dime tu *nombre y apellido* por favor 🙂`;
    await waSendText(to, session.lastPrompt);
    return;
  }

  if (!session.business) {
    session.state = "collect_business";
    session.lastPrompt = `¿Cómo se llama tu negocio? (o tu marca)`;
    await waSendText(to, session.lastPrompt);
    return;
  }

  if (!session.city) {
    session.state = "collect_city";
    session.lastPrompt = `¿En qué ciudad estás? (Ej: Santo Domingo)`;
    await waSendText(to, session.lastPrompt);
    return;
  }

  if (!session.link) {
    session.state = "collect_link";
    session.lastPrompt = `Opcional: pásame tu *Instagram o web* (si tienes) para entender mejor tu caso. Si no, escribe *No tengo*.`;
    await waSendText(to, session.lastPrompt);
    return;
  }

  // done
  session.state = "done";
  await waSendText(
    to,
    `✅ Perfecto, ya tengo lo necesario.\n\nEn breve te enviamos una recomendación y próximos pasos.\nSi deseas, también puedo pasarte con un asesor ahora mismo.`
  );
  await sendCloseMenu(to);

  // notify admin with summary
  await notifyAdmin(session, to);
}

async function handleCloseChoice(to, session, choiceId) {
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
// Webhook verify
// =====================================================
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) return res.status(200).send(challenge);
  return res.sendStatus(403);
});

// =====================================================
// Webhook receive
// =====================================================
app.post("/webhook", async (req, res) => {
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

    // Quick intents
    if (isHumanRequest(tNorm)) {
      session.goal = "Hablar con humano";
      await waSendText(from, `Claro ✅ Te paso con un asesor.\nDime en una línea qué necesitas (tipo de bot y negocio).`);
      await notifyAdmin({ ...session, notes: (session.notes || "") + " | Pidió HUMANO (keyword)" }, from);
      return res.sendStatus(200);
    }

    // Anti-raro phrase handling
    if (tNorm.includes("como vendes") || tNorm.includes("y tu no tienes") || tNorm.includes("raro") || tNorm.includes("no tienes uno")) {
      await waSendText(from, antiRaroText());
      // keep funnel
      if (!session.goal) session.goal = "Quiero un bot";
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
      await waSendText(from, `Perfecto ✅ Vamos a elegir el bot ideal.`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }
    if (userText === "goal_prices") {
      session.goal = "Info / precios";
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }
    if (userText === "goal_demo") {
      session.goal = "Agendar demo";
      await stepAskNext(from, session);
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
      session.goal = session.goal || "Info / precios";
      await waSendText(from, pricingInfoText());
      // Keep funnel
      if (!session.botType) {
        await sendBotTypes(from);
        session.state = "collect_bot_type";
      } else {
        await stepAskNext(from, session);
      }
      return res.sendStatus(200);
    }

    // If user asks demo at any time
    if (isDemoIntent(tNorm) && session.state !== "done") {
      session.goal = session.goal || "Agendar demo";
      await waSendText(from, `Perfecto ✅ Para preparar la demo, te haré unas preguntas rápidas.`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

    // Handle structured flow states
    if (session.state === "collect_bot_type") {
      if (label && label.startsWith("Bot") || label === "Automatizaciones" || label === "No sé / Recomiéndame") {
        session.botType = label;
        await waSendText(from, `Genial ✅`);
        await stepAskNext(from, session);
        return res.sendStatus(200);
      }
      // Accept free text bot type
      if (tNorm.length >= 2) {
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

    if (session.state === "collect_channels") {
      if (label) session.channels = label;
      else session.channels = safeText(userText, 120);
      await waSendText(from, `✅`);
      await stepAskNext(from, session);
      return res.sendStatus(200);
    }

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

    if (session.state === "done") {
      // If done, treat as notes or AI follow-up
      if (tNorm.length > 2) {
        session.notes = safeText((session.notes ? session.notes + " | " : "") + userText, 400);
        await waSendText(from, `Perfecto ✅ ¿Quieres *demo*, *cotización* o *humano*?`);
        await sendCloseMenu(from);
        await notifyAdmin({ ...session, notes: (session.notes || "") + " | Mensaje post-done" }, from);
        return res.sendStatus(200);
      }
    }

    // If none matched and still no goal -> show menu
    if (!session.goal) {
      await sendMainMenu(from);
      return res.sendStatus(200);
    }

    // Fallback: use ChatGPT to answer + keep funnel
    const aiReply = await callOpenAI({
      userId: from,
      userPhone: from,
      userText,
      session,
    });

    if (aiReply) {
      await waSendText(from, aiReply);
    }

    // After AI, continue funnel if incomplete
    const needsMore =
      !session.botType || !session.sector || !session.objective || !session.channels || !session.volume || !session.urgency || !session.name || !session.business || !session.city || !session.link;

    if (needsMore) {
      await stepAskNext(from, session);
    } else if (session.state !== "done") {
      session.state = "done";
      await sendCloseMenu(from);
      await notifyAdmin(session, from);
    }

    return res.sendStatus(200);
  } catch (e) {
    console.error("Webhook error:", e?.response?.data || e?.message || e);
    return res.sendStatus(200);
  }
});

// Health
app.get("/", (_req, res) => res.send("OK"));

// Start
app.listen(PORT, () => console.log(`✅ ${BRAND_NAME} bot running on :${PORT}`));
