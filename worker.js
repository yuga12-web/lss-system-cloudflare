import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const json = (
  data,
  status = 200,
  extraHeaders = {}
) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type":
        "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });

const b64url = {
  encode(bytes) {
    let value = "";

    for (const byte of bytes) {
      value += String.fromCharCode(byte);
    }

    return btoa(value)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  },

  decode(value) {
    value = value
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    value += "=".repeat(
      (4 - (value.length % 4)) % 4
    );

    return Uint8Array.from(
      atob(value),
      character =>
        character.charCodeAt(0)
    );
  },
};

function challenge() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return b64url.encode(bytes);
}

const originOf = request =>
  new URL(request.url).origin;

const rpIdOf = request =>
  new URL(request.url).hostname;

async function bodyOf(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function cookieOf(request, name) {
  const header =
    request.headers.get("cookie") || "";

  for (const part of header.split(";")) {
    const [key, ...rest] =
      part.trim().split("=");

    if (key === name) {
      return rest.join("=");
    }
  }

  return null;
}

/* ========================================
   保護された画面を返す
======================================== */

async function sessionStatus(request, env) {
  const token = cookieOf(request, "lss_session");

  const authenticated = token
    ? await env.LSS_AUTH.get(`session:${token}`)
    : null;

  return json({
    authenticated: Boolean(authenticated),
  });
}
async function serveApp(request, env) {
  if (!env.ASSETS) {
    return json({
      service: "LSS AUTH",
      status: "ONLINE",
    });
  }

  const assetResponse =
    await env.ASSETS.fetch(request);

  const contentType =
    assetResponse.headers.get(
      "content-type"
    ) || "";

  if (
    !contentType.includes("text/html")
  ) {
    return assetResponse;
  }

  let html =
    await assetResponse.text();

  const token =
    cookieOf(
      request,
      "lss_session"
    );

  const sessionKey =
    token
      ? `session:${token}`
      : null;

  const authenticated =
    sessionKey
      ? await env.LSS_AUTH.get(
          sessionKey
        )
      : null;

  const headers =
    new Headers(
      assetResponse.headers
    );

  headers.set(
    "content-type",
    "text/html; charset=utf-8"
  );

  headers.set(
    "cache-control",
    "no-store, private"
  );

  headers.set(
    "x-content-type-options",
    "nosniff"
  );

  headers.set(
    "x-frame-options",
    "DENY"
  );

  headers.set(
    "referrer-policy",
    "no-referrer"
  );

  if (authenticated) {
    /*
     認証済みの場合だけ、
     ホーム画像入りのHTMLを返す。
    */


    html = html
      .replace(
        '<section id="lock" class="screen lock active">',
        '<section id="lock" class="screen lock">'
      )
      .replace(
        '<section id="granted" class="screen granted">',
        '<section id="granted" class="screen granted active">'
      );
  } else {
    /*
     未認証の場合は、
     ホーム画像のデータを削除してから返す。
    */

    html = html.replace(
      /(<section id="home"[\s\S]*?<img\s+src=")data:image\/jpeg;base64,[^"]+("[\s\S]*?<\/section>)/,
      "$1$2"
    );

    /*
     Face ID成功後に一度だけ再読み込みし、
     Worker側で認証Cookieを確認する。
    */

    html = html.replace(
      /showScreen\(\s*["']granted["']\s*\);/,
      "window.location.reload();"
    );
  }

  return new Response(html, {
    status: assetResponse.status,
    headers,
  });
}

/* ========================================
   初回本人登録
======================================== */

async function registerOptions(
  request,
  env
) {
  /*
   一度登録されたら、
   別のパスキーで上書きできない。
  */

  const existingCredential =
    await env.LSS_AUTH.get(
      "credential"
    );

  if (existingCredential) {
    return json(
      {
        error:
          "このLSSには本人登録済みです",
      },
      409
    );
  }

  const currentChallenge =
    challenge();

  const userId =
    b64url.encode(
      crypto.getRandomValues(
        new Uint8Array(32)
      )
    );

  await Promise.all([
    env.LSS_AUTH.put(
      "register_challenge",
      currentChallenge,
      {
        expirationTtl: 300,
      }
    ),

    env.LSS_AUTH.put(
      "user_id",
      userId
    ),
  ]);

  return json({
    challenge:
      currentChallenge,

    rp: {
      name:
        "LIFE STATUS SYSTEM",

      id:
        rpIdOf(request),
    },

    user: {
      id:
        userId,

      name:
        "lss-owner",

      displayName:
        "LSS Owner",
    },

    pubKeyCredParams: [
      {
        type:
          "public-key",

        alg:
          -7,
      },

      {
        type:
          "public-key",

        alg:
          -257,
      },
    ],

    authenticatorSelection: {
      authenticatorAttachment:
        "platform",

      residentKey:
        "preferred",

      requireResidentKey:
        false,

      userVerification:
        "required",
    },

    timeout:
      60000,

    attestation:
      "none",
  });
}

/* ========================================
   初回登録の署名確認
======================================== */

async function registerVerify(
  request,
  env
) {
  const existingCredential =
    await env.LSS_AUTH.get(
      "credential"
    );

  if (existingCredential) {
    return json(
      {
        error:
          "このLSSには本人登録済みです",
      },
      409
    );
  }

  const response =
    await bodyOf(request);

  const expectedChallenge =
    await env.LSS_AUTH.get(
      "register_challenge"
    );

  if (
    !response ||
    !expectedChallenge
  ) {
    return json(
      {
        error:
          "登録セッションが無効です",
      },
      400
    );
  }

  try {
    const verification =
      await verifyRegistrationResponse({
        response,

        expectedChallenge,

        expectedOrigin:
          originOf(request),

        expectedRPID:
          rpIdOf(request),

        requireUserVerification:
          true,
      });

    if (
      !verification.verified ||
      !verification.registrationInfo
    ) {
      return json(
        {
          error:
            "登録署名を確認できませんでした",
        },
        401
      );
    }

    const { credential } =
      verification
        .registrationInfo;

    await Promise.all([
      env.LSS_AUTH.put(
        "credential",
        JSON.stringify({
          id:
            credential.id,

          publicKey:
            b64url.encode(
              credential.publicKey
            ),

          counter:
            credential.counter,

          transports:
            response.response
              ?.transports ||
            credential.transports ||
            [],
        })
      ),

      env.LSS_AUTH.delete(
        "register_challenge"
      ),
    ]);

    return json({
      ok: true,
      registered: true,
    });
  } catch (error) {
    console.error(
      "registration verification failed",
      error
    );

    return json(
      {
        error:
          "Face IDの登録署名を確認できませんでした",
      },
      401
    );
  }
}

/* ========================================
   Face IDログイン設定
======================================== */

async function authOptions(
  request,
  env
) {
  const raw =
    await env.LSS_AUTH.get(
      "credential"
    );

  if (!raw) {
    return json(
      {
        error:
          "Passkey has not been registered yet",
      },
      409
    );
  }

  const credential =
    JSON.parse(raw);

  const currentChallenge =
    challenge();

  await env.LSS_AUTH.put(
    "auth_challenge",
    currentChallenge,
    {
      expirationTtl: 300,
    }
  );

  return json({
    challenge:
      currentChallenge,

    rpId:
      rpIdOf(request),

    allowCredentials: [
      {
        id:
          credential.id,

        type:
          "public-key",

        transports:
          credential.transports ||
          [
            "internal",
            "hybrid",
          ],
      },
    ],

    userVerification:
      "required",

    timeout:
      60000,
  });
}

/* ========================================
   Face ID署名確認
======================================== */

async function authVerify(
  request,
  env
) {
  const response =
    await bodyOf(request);

  const [
    expectedChallenge,
    raw,
  ] = await Promise.all([
    env.LSS_AUTH.get(
      "auth_challenge"
    ),

    env.LSS_AUTH.get(
      "credential"
    ),
  ]);

  if (
    !response ||
    !expectedChallenge ||
    !raw
  ) {
    return json(
      {
        error:
          "認証セッションが無効です",
      },
      400
    );
  }

  const stored =
    JSON.parse(raw);

  if (response.id !== stored.id) {
    return json(
      {
        error:
          "登録されていない認証情報です",
      },
      401
    );
  }

  try {
    const verification =
      await verifyAuthenticationResponse({
        response,

        expectedChallenge,

        expectedOrigin:
          originOf(request),

        expectedRPID:
          rpIdOf(request),

        requireUserVerification:
          true,

        credential: {
          id:
            stored.id,

          publicKey:
            b64url.decode(
              stored.publicKey
            ),

          counter:
            stored.counter || 0,

          transports:
            stored.transports || [],
        },
      });

    if (!verification.verified) {
      return json(
        {
          error:
            "Face IDの署名を確認できませんでした",
        },
        401
      );
    }

    stored.counter =
      verification
        .authenticationInfo
        .newCounter;

    /*
     認証後に一度だけ使える
     サーバー側セッションを発行する。
    */

    const sessionToken =
      challenge();

    await Promise.all([
      env.LSS_AUTH.put(
        "credential",
        JSON.stringify(stored)
      ),

      env.LSS_AUTH.delete(
        "auth_challenge"
      ),

      env.LSS_AUTH.put(
        `session:${sessionToken}`,
        "verified",
        {
          expirationTtl: 120,
        }
      ),
    ]);

    return json(
      {
        ok: true,
        authenticated: true,
      },
      200,
      {
        "set-cookie": [
          `lss_session=${sessionToken}`,
          "Path=/",
          "HttpOnly",
          "Secure",
          "SameSite=Strict",
          "Max-Age=120",
        ].join("; "),
      }
    );
  } catch (error) {
    console.error(
      "authentication verification failed",
      error
    );

    return json(
      {
        error:
          "Face IDの署名を確認できませんでした",
      },
      401
    );
  }
}

/* ========================================
   6桁コード認証
======================================== */

async function pinClientId(request) {
  const ip =
    request.headers.get(
      "CF-Connecting-IP"
    ) || "unknown";

  const bytes =
    new TextEncoder().encode(ip);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      bytes
    );

  return b64url.encode(
    new Uint8Array(digest)
  );
}


function safePinEqual(input, secret) {
  if (
    input.length !== secret.length
  ) {
    return false;
  }

  let difference = 0;

  for (
    let index = 0;
    index < input.length;
    index++
  ) {
    difference |=
      input.charCodeAt(index) ^
      secret.charCodeAt(index);
  }

  return difference === 0;
}


async function pinVerify(
  request,
  env
) {
  /*
   6桁はGitHubに保存せず、
   Cloudflare Secretから読み込む。
  */

  const secret =
    String(env.LSS_PIN || "")
      .trim();

  if (!/^\d{6}$/.test(secret)) {
    return json(
      {
        error:
          "6桁コードがまだ設定されていません",
      },
      503
    );
  }

  const body =
    await bodyOf(request);

  const pin =
    String(body?.pin || "")
      .replace(/\D/g, "")
      .slice(0, 6);

  const clientId =
    await pinClientId(request);

  const failKey =
    `pin_fail:${clientId}`;

  const lockKey =
    `pin_lock:${clientId}`;

  const locked =
    await env.LSS_AUTH.get(
      lockKey
    );

  if (locked) {
    return json(
      {
        error:
          "入力回数が上限に達しました。15分後にもう一度試してください",
        locked: true,
        retryAfter: 900,
      },
      429
    );
  }

  const correct =
    /^\d{6}$/.test(pin) &&
    safePinEqual(
      pin,
      secret
    );

  if (!correct) {
    const previous =
      Number(
        await env.LSS_AUTH.get(
          failKey
        )
      ) || 0;

    const failures =
      previous + 1;

    if (failures >= 5) {
      await Promise.all([
        env.LSS_AUTH.put(
          lockKey,
          "locked",
          {
            expirationTtl: 900,
          }
        ),

        env.LSS_AUTH.delete(
          failKey
        ),
      ]);

      return json(
        {
          error:
            "5回間違えたため15分間ロックしました",
          locked: true,
          retryAfter: 900,
        },
        429
      );
    }

    await env.LSS_AUTH.put(
      failKey,
      String(failures),
      {
        expirationTtl: 900,
      }
    );

    return json(
      {
        error:
          `コードが違います。残り${5 - failures}回です`,
        remaining:
          5 - failures,
      },
      401
    );
  }

  await Promise.all([
    env.LSS_AUTH.delete(
      failKey
    ),

    env.LSS_AUTH.delete(
      lockKey
    ),
  ]);

  /*
   Face IDと同じ一度だけ使える
   認証セッションを発行する。
  */

  const sessionToken =
    challenge();

  await env.LSS_AUTH.put(
    `session:${sessionToken}`,
    "verified",
    {
      expirationTtl: 120,
    }
  );

  return json(
    {
      ok: true,
      authenticated: true,
    },
    200,
    {
      "set-cookie": [
        `lss_session=${sessionToken}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Max-Age=120",
      ].join("; "),
    }
  );
}
/* ========================================
   Cloudflare Worker
======================================== */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    /*
     GETの場合は、
     認証状態に応じた画面を返す。
    */

    if (request.method !== "POST") {
      return serveApp(
        request,
        env
      );
    }

    try {
      switch (url.pathname) {
        case "/api/passkey/register/options":
          return registerOptions(
            request,
            env
          );

        case "/api/passkey/register/verify":
          return registerVerify(
            request,
            env
          );

        case "/api/passkey/auth/options":
          return authOptions(
            request,
            env
          );
          case "/api/passkey/auth/verify":
  return authVerify(
    request,
    env
  );

        case "/api/pin/verify":
  return pinVerify(
    request,
    env
  );

case "/api/session/status":
  return sessionStatus(
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