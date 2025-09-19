const crypto = require("crypto");
const fs = require("fs");

const SERVICE_ACCOUNT_FILE = "./sisadm-expensas-28655ffce6fd.json";

const service_account = JSON.parse(fs.readFileSync(SERVICE_ACCOUNT_FILE));

const SCOPE = "https://www.googleapis.com/auth/firebase.messaging";

const toB64Url = (obj) =>
  // Lo codifica en base64url
  Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");

const getAccessToken = async () => {

  // Encabezado del JWT
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid: service_account.private_key_id,
  };

  // Cuerpo de JWT
  const claim_set = {
    iss: service_account.client_email,
    scope: SCOPE,
    aud: "https://oauth2.googleapis.com/token",
    exp: Math.floor(Date.now() / 1000) + 60 * 60, // 1 hora
    iat: Math.floor(Date.now() / 1000),
  };

  // Codifica el encabezado y el cuerpo en base64url
  const encodedHeader = toB64Url(header);
  const encodedClaim_set = toB64Url(claim_set);

  // Crea la cadena para firmar
  const signingInput = `${encodedHeader}.${encodedClaim_set}`;

  // Firma RSASSA-PKCS1-v1_5 con SHA-256 (RS256)
  // Algoritmo de firma RSA-SHA256
  const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput, "utf8"), {
    key: service_account.private_key,
  });

  const encodedSignature = Buffer.from(signature).toString("base64url");

  const jwt = `${signingInput}.${encodedSignature}`;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }).toString(),
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(`Token exchange failed: ${res.status} ${res.statusText} - ${JSON.stringify(data)}`);
  }

  console.log(data.access_token)

  return data.access_token;
};

getAccessToken();