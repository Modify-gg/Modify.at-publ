const net = require("net");
const tls = require("tls");

function readMultiline(socket, state) {
  return new Promise((resolve, reject) => {
    let buffer = "";

    function cleanup() {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    }

    function onError(error) {
      cleanup();
      reject(error);
    }

    function onClose() {
      cleanup();
      reject(new Error("SMTP connection closed unexpectedly."));
    }

    function onData(chunk) {
      buffer += chunk.toString("utf8");
      const lines = buffer.split("\r\n").filter(Boolean);
      if (!lines.length) {
        return;
      }

      const lastLine = lines[lines.length - 1];
      if (/^\d{3} /.test(lastLine)) {
        cleanup();
        state.lastResponse = buffer.trim();
        resolve(state.lastResponse);
      }
    }

    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

async function sendCommand(socket, state, command, expectedCodes) {
  socket.write(`${command}\r\n`);
  const response = await readMultiline(socket, state);
  const code = Number(response.slice(0, 3));
  if (!expectedCodes.includes(code)) {
    throw new Error(`SMTP command failed: ${command} -> ${response}`);
  }
  return response;
}

function createConnection(config) {
  return new Promise((resolve, reject) => {
    const options = {
      host: config.host,
      port: config.port,
      servername: config.host,
    };

    const handleConnect = () => resolve(socket);
    const handleError = (error) => reject(error);

    const socket = config.secure
      ? tls.connect(options, handleConnect)
      : net.createConnection(options, handleConnect);

    socket.once("error", handleError);
  });
}

function encodeBase64(value) {
  return Buffer.from(value, "utf8").toString("base64");
}

function buildMessage({ from, to, subject, text }) {
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="utf-8"',
    "Content-Transfer-Encoding: 7bit",
    "",
    text,
  ].join("\r\n");
}

async function sendMail({ to, subject, text }) {
  const config = {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 465),
    secure: process.env.SMTP_SECURE !== "false",
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.SMTP_FROM || "support@modify.at",
  };

  if (!config.host || !config.user || !config.pass) {
    throw new Error("SMTP is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, and optionally SMTP_FROM.");
  }

  const state = { lastResponse: "" };
  const socket = await createConnection(config);

  try {
    const greeting = await readMultiline(socket, state);
    if (!greeting.startsWith("220")) {
      throw new Error(`SMTP greeting failed: ${greeting}`);
    }

    await sendCommand(socket, state, "EHLO modify.at", [250]);
    await sendCommand(socket, state, "AUTH LOGIN", [334]);
    await sendCommand(socket, state, encodeBase64(config.user), [334]);
    await sendCommand(socket, state, encodeBase64(config.pass), [235]);
    await sendCommand(socket, state, `MAIL FROM:<${config.from}>`, [250]);
    await sendCommand(socket, state, `RCPT TO:<${to}>`, [250, 251]);
    await sendCommand(socket, state, "DATA", [354]);

    const message = buildMessage({
      from: config.from,
      to,
      subject,
      text,
    }).replace(/\r?\n\./g, "\r\n..");

    socket.write(`${message}\r\n.\r\n`);
    const queued = await readMultiline(socket, state);
    if (!queued.startsWith("250")) {
      throw new Error(`SMTP DATA failed: ${queued}`);
    }

    await sendCommand(socket, state, "QUIT", [221]);
  } finally {
    socket.end();
  }
}

async function sendWelcomeEmail(user) {
  await sendMail({
    to: user.email,
    subject: "Account successfully made!",
    text: `Hi ${user.username},\n\nAccount successfully made!\n\nWelcome to modify.at.\n`,
  });
}

module.exports = {
  sendWelcomeEmail,
};
