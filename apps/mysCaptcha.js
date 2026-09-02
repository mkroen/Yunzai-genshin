import crypto from "node:crypto"
import fetch from "node-fetch"
import GsCfg from "../model/gsCfg.js"

const ROUTE_PREFIX = "/mys-captcha/"
const SOLVED_REUSE_MS = 30 * 1000
const GLOBAL_STATE = Symbol.for("yunzai-genshin.mys-captcha.state")
const REGISTERED = Symbol.for("yunzai-genshin.mys-captcha.registered")
const CHALLENGE_META = {
  gs: {
    "x-rpc-challenge_game": "2",
    "x-rpc-page": "v4.1.5-ys_#ys",
    "x-rpc-tool-verison": "v4.1.5-ys",
  },
  sr: {
    "x-rpc-challenge_game": "6",
    "x-rpc-page": "v1.4.1-rpg_#/rpg",
    "x-rpc-tool-verison": "v1.4.1-rpg",
  },
  zzz: {
    "x-rpc-challenge_game": "8",
    "x-rpc-page": "v1.0.14_#/zzz",
    "x-rpc-tool-verison": "v1.0.14-zzz",
  },
}

function state() {
  const value = (globalThis[GLOBAL_STATE] ??= {})
  value.sessions ??= new Map()
  value.active ??= new Map()
  return value
}

function challengeHeaders(mysApi, game, query = "", body = "") {
  return {
    ...mysApi.getHeaders(query, body),
    ...(CHALLENGE_META[game] || CHALLENGE_META.gs),
    Cookie: mysApi.cookie,
    ...(mysApi._device_fp?.data?.device_fp
      ? { "x-rpc-device_fp": mysApi._device_fp.data.device_fp }
      : {}),
  }
}

async function createVerification(mysApi, game = "gs") {
  const query = "is_high=false"
  const response = await fetch(
    `https://api-takumi-record.mihoyo.com/game_record/app/card/wapi/createVerification?${query}`,
    {
      headers: challengeHeaders(mysApi, game, query),
      timeout: 10000,
    },
  )
  if (!response.ok) throw new Error(`createVerification HTTP ${response.status}`)
  const result = await response.json()
  if (result?.retcode !== 0 || !result?.data?.gt || !result?.data?.challenge) {
    throw new Error(`createVerification retcode=${result?.retcode ?? "unknown"}`)
  }
  return result.data
}

async function verifyVerification(mysApi, game, solved) {
  const challenge = solved.original_challenge || solved.geetest_challenge
  const data = {
    geetest_challenge: challenge,
    geetest_validate: solved.geetest_validate,
    geetest_seccode: `${solved.geetest_validate}|jordan`,
  }
  const body = JSON.stringify(data)
  const response = await fetch(
    "https://api-takumi-record.mihoyo.com/game_record/app/card/wapi/verifyVerification",
    {
      method: "post",
      headers: {
        ...challengeHeaders(mysApi, game, "", body),
        "Content-Type": "application/json",
      },
      body,
      timeout: 10000,
    },
  )
  if (!response.ok) throw new Error(`verifyVerification HTTP ${response.status}`)
  const result = await response.json()
  if (result?.retcode !== 0) {
    throw new Error(`verifyVerification retcode=${result?.retcode ?? "unknown"}`)
  }
  logger.mark(`[米游社验证码] 官方验证提交成功 game=${game}`)
  return result?.data?.challenge || challenge
}

function captchaHtml(token, challenge, timeoutSeconds) {
  const safeChallenge = JSON.stringify(challenge).replaceAll("<", "\\u003c")
  const safeToken = JSON.stringify(token)
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="referrer" content="no-referrer">
  <title>米游社安全验证</title>
  <style>
    body{margin:0;background:#f5f3ff;color:#1f2340;font-family:system-ui,-apple-system,sans-serif}
    main{max-width:420px;margin:0 auto;padding:32px 20px;text-align:center}
    .card{background:#fff;border:1px solid #e5e0ff;border-radius:20px;padding:24px;box-shadow:0 12px 32px rgba(70,60,160,.10)}
    h1{font-size:22px;margin:0 0 10px}.tip{color:#6b7280;line-height:1.6;margin:0 0 24px}
    #captcha{display:flex;justify-content:center;min-height:48px}.status{margin-top:18px;color:#6b7280}
  </style>
  <script src="https://static.geetest.com/static/js/gt.0.5.0.js"></script>
</head>
<body><main><div class="card"><h1>米游社安全验证</h1><p class="tip">完成滑块后，Yunzai 会自动重试刚才的查询。链接 ${timeoutSeconds} 秒内有效且只能使用一次。</p><div id="captcha"></div><div class="status" id="status">正在加载验证组件…</div></div></main>
<script>
const challenge=${safeChallenge};const token=${safeToken};const status=document.getElementById("status");
initGeetest({gt:challenge.gt,challenge:challenge.challenge,new_captcha:challenge.new_captcha,offline:!challenge.success,product:"bind",width:"100%",https:location.protocol==="https:",api_server:"api.geetest.com",lang:"zh-cn"},captcha=>{
  captcha.appendTo("#captcha");captcha.onReady(()=>{status.textContent="请完成下方滑块验证";captcha.verify()});
  captcha.onError(()=>{status.textContent="验证组件加载失败，请关闭页面后重新发起查询"});
  captcha.onSuccess(async()=>{status.textContent="正在提交验证结果…";const result=captcha.getValidate();
    try{const response=await fetch("${ROUTE_PREFIX}"+token,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(result)});
      if(!response.ok)throw new Error();document.querySelector(".card").innerHTML="<h1>验证完成</h1><p class='tip'>可以关闭此页面，Yunzai 正在重试查询。</p>";
    }catch{status.textContent="提交失败，请保持在同一网络后重试"}
  });
});
</script></body></html>`
}

function registerRoutes() {
  if (globalThis[REGISTERED]) return
  globalThis[REGISTERED] = true
  Bot.express.skip_auth.push(ROUTE_PREFIX)
  Bot.express.quiet.push(ROUTE_PREFIX)

  Bot.express.get(`${ROUTE_PREFIX}:token`, (req, res) => {
    const session = state().sessions.get(req.params.token)
    if (!session || session.expiresAt < Date.now()) {
      state().sessions.delete(req.params.token)
      return res.status(410).send("验证链接已失效，请重新发起查询。")
    }
    res
      .type("html")
      .send(captchaHtml(req.params.token, session.challenge, session.timeoutSeconds))
  })

  Bot.express.post(`${ROUTE_PREFIX}:token`, (req, res) => {
    const session = state().sessions.get(req.params.token)
    const result = req.body || {}
    if (!session || session.expiresAt < Date.now()) {
      state().sessions.delete(req.params.token)
      return res.status(410).json({ ok: false })
    }
    if (!result.geetest_challenge || !result.geetest_validate || !result.geetest_seccode) {
      return res.status(400).json({ ok: false })
    }
    state().sessions.delete(req.params.token)
    logger.mark("[米游社验证码] 浏览器回调已接收")
    session.resolve({ ...result, original_challenge: session.challenge.challenge })
    res.json({ ok: true })
  })
}

function waitForVerification(challenge, timeoutSeconds) {
  const token = crypto.randomBytes(24).toString("hex")
  const ttlMs = timeoutSeconds * 1000
  let timer
  const result = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      state().sessions.delete(token)
      reject(new Error("captcha timeout"))
    }, ttlMs)
    state().sessions.set(token, {
      challenge,
      expiresAt: Date.now() + ttlMs,
      timeoutSeconds,
      resolve(value) {
        clearTimeout(timer)
        resolve(value)
      },
    })
  })
  return { token, result }
}

async function getPendingVerification(key, mysApi, game, timeoutSeconds) {
  const current = state().active.get(key)
  if (current) return { owner: false, pending: await current }

  const creating = (async () => {
    const challenge = await createVerification(mysApi, game)
    return { ...waitForVerification(challenge, timeoutSeconds), verification: null }
  })()
  state().active.set(key, creating)

  try {
    const pending = await creating
    pending.result.catch(() => state().active.delete(key))
    return { owner: true, pending }
  } catch (error) {
    state().active.delete(key)
    throw error
  }
}

async function sendPrivateMessage(e, message) {
  if (e?.bot?.pickFriend) return e.bot.pickFriend(e.user_id).sendMsg(message)
  return Bot.sendFriendMsg(e.self_id, e.user_id, message)
}

async function sendPrivateLink(e, link, timeoutSeconds) {
  return sendPrivateMessage(
    e,
    `米游社查询触发了安全验证，请在 ${timeoutSeconds} 秒内完成：\n${link}`,
  )
}

function handled(res) {
  return { ...(res || {}), _captchaHandled: true }
}

export class mysCaptcha extends plugin {
  constructor() {
    super({
      name: "米游社验证码",
      dsc: "处理米游社游戏记录接口的滑块验证",
      event: "message",
      priority: 50,
      namespace: "genshin-mys-captcha",
      handler: [{ key: "mys.req.err", fn: "handleMysError", priority: 50 }],
      rule: [],
    })
  }

  init() {
    registerRoutes()
  }

  async handleMysError(e, { mysApi, type, res, data }, reject) {
    if (![1034, 10035].includes(Number(res?.retcode)) || !mysApi?.cookie) {
      reject("非验证码错误")
      return res
    }

    const settings = GsCfg.getConfig("mys", "set") || {}
    if (settings.captchaEnabled !== true) {
      reject("验证码服务未启用")
      return res
    }

    const mode = settings.captchaMode === "all" ? "all" : "allowlist"
    const allowUsers = new Set((settings.captchaAllowUsers || []).map(String))
    if (mode !== "all" && !allowUsers.has(String(e.user_id))) {
      reject("用户不在验证码灰度白名单")
      return res
    }

    if (e.isGroup) {
      if (!e._mysCaptchaGroupNotified) {
        e._mysCaptchaGroupNotified = true
        await e.reply("米游社查询遇到验证码，请私聊发送相同命令并完成验证。")
      }
      return handled(res)
    }

    if (e._mysCaptchaFailed) return handled(res)

    const baseUrl = String(settings.captchaBaseUrl || "").replace(/\/$/, "")
    if (!baseUrl) {
      reject("未配置 captchaBaseUrl")
      return res
    }
    const timeoutSeconds = Math.min(
      300,
      Math.max(30, Number(settings.captchaTimeoutSeconds) || 120),
    )

    try {
      const cookieId = crypto.createHash("sha256").update(mysApi.cookie).digest("hex").slice(0, 16)
      const activeKey = `${e.user_id}:${mysApi.uid}:${cookieId}`
      const { owner, pending } = await getPendingVerification(
        activeKey,
        mysApi,
        mysApi.game,
        timeoutSeconds,
      )
      const link = `${baseUrl}${ROUTE_PREFIX}${pending.token}`
      if (owner) {
        await sendPrivateLink(e, link, timeoutSeconds)
      }
      const solved = await pending.result
      pending.verification ??= verifyVerification(mysApi, mysApi.game, solved)
      let verifiedChallenge
      try {
        verifiedChallenge = await pending.verification
      } catch (error) {
        state().active.delete(activeKey)
        throw error
      }
      const clearTimer = setTimeout(
        () => state().active.delete(activeKey),
        SOLVED_REUSE_MS,
      )
      clearTimer.unref?.()
      return await mysApi.getData(type, {
        ...(data || {}),
        headers: {
          ...(data?.headers || {}),
          "x-rpc-challenge": verifiedChallenge,
        },
      })
    } catch (error) {
      logger.warn(`[米游社验证码] ${error.message}`)
      e._mysCaptchaFailed = true
      if (!e._mysCaptchaFailureReplied) {
        e._mysCaptchaFailureReplied = true
        await sendPrivateMessage(e, "未通过验证码，请重试")
      }
      return handled(res)
    }
  }
}
