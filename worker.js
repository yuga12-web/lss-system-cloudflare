/**
 * LIFE STATUS SYSTEM
 * Passkey / Face ID Authentication Worker
 */

const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });

const base64url = {
  encode(input) {
    const bytes =
      input instanceof Uint8Array ? input : new Uint8Array(input);

    let binary = "";

    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }

    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  },

  decode(input) {
    let value = input.replace(/-/g, "+").replace(/_/g, "/");

    value += "=".repeat((4 - (value.length % 4)) % 4);

    const binary = atob(value);

    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  },
};

function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomChallenge() {
  return base64url.encode(randomBytes(32));
}

function getOrigin(request) {
  return new URL(request.url).origin;
}

function getRpId(request) {
  return new URL(request.url).hostname;
}

async function readJSON(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/*
 * ==========================================================
 * REGISTER OPTIONS
 * ==========================================================
 */

async function registerOptions(request, env) {
  const challenge = randomChallenge();

  await env.LSS_AUTH.put(
    "register_challenge",
    challenge,
    {
      expirationTtl: 300,
    }
  );

  const userId = base64url.encode(randomBytes(32));

  await env.LSS_AUTH.put(
    "user_id",
    userId
  );

  return json({
    challenge,

    rp: {
      name: "LIFE STATUS SYSTEM",
      id: getRpId(request),
    },

    user: {
      id: userId,
      name: "lss-owner",
      displayName: "LSS Owner",
    },

    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7,
      },
      {
        type: "public-key",
        alg: -257,
      },
    ],

    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      requireResidentKey: false,
      userVerification: "required",
    },

    timeout: 60000,

    attestation: "none",
  });
}

/*
 * ==========================================================
 * REGISTER VERIFY
 * ==========================================================
 *
 * 初回登録情報を保存する。
 *
 * 注意：
 * WebAuthnの完全な暗号学的検証には
 * attestationObject のCBOR解析と公開鍵抽出が必要。
 * このWorker単体ではそこを省略しないと成立しないため、
 * ここではcredential自体を登録情報として保存する。
 */

async function registerVerify(request, env) {
  const body = await readJSON(request);

  if (!body || !body.id || !body.response) {
    return json(
      {
        error: "登録データが不正です",
      },
      400
    );
  }

  const challenge =
    await env.LSS_AUTH.get(
      "register_challenge"
    );

  if (!challenge) {
    return json(
      {
        error:
          "登録セッションの有効期限が切れています",
      },
      400
    );
  }

  /*
   * Credential ID を保存
   */

  await env.LSS_AUTH.put(
    "credential_id",
    body.id
  );

  await env.LSS_AUTH.put(
    "credential_raw",
    JSON.stringify(body)
  );

  await env.LSS_AUTH.delete(
    "register_challenge"
  );

  return json({
    ok: true,
    registered: true,
  });
}

/*
 * ==========================================================
 * AUTH OPTIONS
 * ==========================================================
 */

async function authOptions(request, env) {
  const credentialId =
    await env.LSS_AUTH.get(
      "credential_id"
    );

  /*
   * まだFace ID / Passkeyが登録されていない
   */

  if (!credentialId) {
    return json(
      {
        error:
          "Passkey has not been registered yet",
      },
      409
    );
  }

  const challenge = randomChallenge();

  await env.LSS_AUTH.put(
    "auth_challenge",
    challenge,
    {
      expirationTtl: 300,
    }
  );

  return json({
    challenge,

    rpId: getRpId(request),

    allowCredentials: [
      {
        id: credentialId,
        type: "public-key",
        transports: [
          "internal",
          "hybrid",
        ],
      },
    ],

    userVerification: "required",

    timeout: 60000,
  });
}

/*
 * ==========================================================
 * AUTH VERIFY
 * ==========================================================
 */

async function authVerify(request, env) {
  const body = await readJSON(request);

  if (
    !body ||
    !body.id ||
    !body.response ||
    !body.response.signature ||
    !body.response.authenticatorData ||
    !body.response.clientDataJSON
  ) {
    return json(
      {
        error: "認証データが不正です",
      },
      400
    );
  }

  const challenge =
    await env.LSS_AUTH.get(
      "auth_challenge"
    );

  if (!challenge) {
    return json(
      {
        error:
          "認証セッションの有効期限が切れています",
      },
      400
    );
  }

  const registeredCredential =
    await env.LSS_AUTH.get(
      "credential_id"
    );

  if (
    !registeredCredential ||
    registeredCredential !== body.id
  ) {
    return json(
      {
        error:
          "登録されていない認証情報です",
      },
      401
    );
  }

  /*
   * clientDataJSON を確認
   */

  try {
    const clientDataBytes =
      base64url.decode(
        body.response.clientDataJSON
      );

    const clientData =
      JSON.parse(
        new TextDecoder().decode(
          clientDataBytes
        )
      );

    if (
      clientData.type !==
      "webauthn.get"
    ) {
      return json(
        {
          error:
            "認証タイプが一致しません",
        },
        401
      );
    }

    if (
      clientData.challenge !==
      challenge
    ) {
      return json(
        {
          error:
            "認証challengeが一致しません",
        },
        401
      );
    }

    if (
      clientData.origin !==
      getOrigin(request)
    ) {
      return json(
        {
          error:
            "認証元が一致しません",
        },
        401
      );
    }
  } catch {
    return json(
      {
        error:
          "認証データを解析できません",
      },
      400
    );
  }

  /*
   * challengeは一度だけ使用
   */

  await env.LSS_AUTH.delete(
    "auth_challenge"
  );

  /*
   * IMPORTANT
   *
   * ここまででFace ID / Passkey UIは起動するが、
   * 本当のWebAuthn認証として完成させるには、
   * 登録時に公開鍵を抽出・保存し、
   * ここでsignatureをその公開鍵で検証する必要がある。
   *
   * 署名検証なしでアクセス許可を出すと
   * 本人認証として安全ではないため、
   * 現段階では成功扱いにしない。
   */

  return json(
    {
      error:
        "Face IDは起動できました。サーバー側の署名検証設定がまだ必要です。",
    },
    501
  );
}

/*
 * ==========================================================
 * WORKER
 * ==========================================================
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin":
            url.origin,

          "access-control-allow-methods":
            "POST, OPTIONS",

          "access-control-allow-headers":
            "content-type",
        },
      });
    }

    if (request.method !== "POST") {
      return json(
        {
          service:
            "LIFE STATUS SYSTEM AUTH",

          status:
            "ONLINE",
        }
      );
    }

    try {
      switch (url.pathname) {
        case "/api/passkey/register/options":
          return await registerOptions(
            request,
            env
          );

        case "/api/passkey/register/verify":
          return await registerVerify(
            request,
            env
          );

        case "/api/passkey/auth/options":
          return await authOptions(
            request,
            env
          );

        case "/api/passkey/auth/verify":
          return await authVerify(
            request,
            env
          );

        default:
          return json(
            {
              error:
                "Not Found",
            },
            404
          );
      }
    } catch (error) {
      console.error(error);

      return json(
        {
          error:
            "LSS authentication server error",
        },
        500
      );
    }
  },
};