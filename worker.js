import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
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

    value += "=".repeat((4 - (value.length % 4)) % 4);

    return Uint8Array.from(
      atob(value),
      character => character.charCodeAt(0)
    );
  },
};

function createChallenge() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return b64url.encode(bytes);
}

const getOrigin = request =>
  new URL(request.url).origin;

const getRpId = request =>
  new URL(request.url).hostname;

async function getBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/* ========================================
   初回登録オプション
======================================== */

async function registerOptions(request, env) {
  /*
   一度本人登録された後は、
   他人が新しいパスキーで上書きできないようにする。
  */
  const existingCredential =
    await env.LSS_AUTH.get("credential");

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
    createChallenge();

  const userId = b64url.encode(
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
    challenge: currentChallenge,

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
      authenticatorAttachment:
        "platform",

      residentKey:
        "preferred",

      requireResidentKey:
        false,

      userVerification:
        "required",
    },

    timeout: 60000,
    attestation: "none",
  });
}

/* ========================================
   初回登録の署名確認
======================================== */

async function registerVerify(
  request,
  env
) {
  /*
   保存直前にも再確認して、
   登録済み情報の上書きを防ぐ。
  */
  const existingCredential =
    await env.LSS_AUTH.get("credential");

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
    await getBody(request);

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
          getOrigin(request),

        expectedRPID:
          getRpId(request),

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
      verification.registrationInfo;

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
   ログインオプション
======================================== */

async function authenticationOptions(
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
    createChallenge();

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
      getRpId(request),

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
   ログイン署名確認
======================================== */

async function authenticationVerify(
  request,
  env
) {
  const response =
    await getBody(request);

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
          getOrigin(request),

        expectedRPID:
          getRpId(request),

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

    await Promise.all([
      env.LSS_AUTH.put(
        "credential",
        JSON.stringify(stored)
      ),

      env.LSS_AUTH.delete(
        "auth_challenge"
      ),
    ]);

    return json({
      ok: true,
      authenticated: true,
    });
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
   Worker
======================================== */

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    if (request.method !== "POST") {
      return env.ASSETS
        ? env.ASSETS.fetch(request)
        : json({
            service:
              "LSS AUTH",
            status:
              "ONLINE",
          });
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
          return authenticationOptions(
            request,
            env
          );

        case "/api/passkey/auth/verify":
          return authenticationVerify(
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