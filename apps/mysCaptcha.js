import crypto from "node:crypto"
import fetch from "node-fetch"
import GsCfg from "../model/gsCfg.js"

const ROUTE_PREFIX = "/mys-captcha/"
const SESSION_TTL_MS = 2 * 60 * 1000
const GLOBAL_STATE = Symbol.for("yunzai-genshin.mys-captcha.state")
const REGISTERED = Symbol.for("yunzai-genshin.mys-captcha.registered")

function state() {
  const value = (globalThis[GLOBAL_STATE] ??= {})
  value.sessions ??= new Map()
  value.active ??= new Map()
  return value
}

function createDs(query = "") {
  const salt = "xV8v4Qu54lUKrEYFZkJhB8cuOh9Asafs"
  const t = Math.floor(Date.now() / 1000)
  const r = crypto.randomInt(100000, 200001)
  const sign = crypto.createHash("md5").update(`salt=${salt}&t=${t}&r=${r}&b=&q=${query}`).digest("hex")
  return `${t},${r},${sign}`
}

async function createVerification(cookie) {
  const query = "is_high=false"
  const response = await fetch(
    `https://api-takumi-record.mihoyo.com/game_record/app/card/wapi/createVerification?${query}`,
    {
      headers: {
        Cookie: cookie,
        DS: createDs(query),
        "x-rpc-app_version": "2.60.1",
        "x-rpc-client_type": "5",
        "x-rpc-challenge_game": "6",
        "x-rpc-page": "v1.4.1-rpg_#/rpg",
        "x-rpc-tool-version": "v1.4.1-rpg",
        "User-Agent": "Mozilla/5.0",
      },
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

function captchaHtml(token, challenge) {
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
<body><main><div class="card"><h1>米游社安全验证</h1><p class="tip">完成滑块后，Yunzai 会自动重试刚才的查询。链接两分钟内有效且只能使用一次。</p><div id="captcha"></div><div class="status" id="status">正在加载验证组件…</div></div></main>
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
    res.type("html").send(captchaHtml(req.params.token, session.challenge))
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
    session.resolve(result)
    res.json({ ok: true })
  })
}

function waitForVerification(challenge) {
  const token = crypto.randomBytes(24).toString("hex")
  let timer
  const result = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      state().sessions.delete(token)
      reject(new Error("captcha timeout"))
    }, SESSION_TTL_MS)
    state().sessions.set(token, {
      challenge,
      expiresAt: Date.now() + SESSION_TTL_MS,
      resolve(value) {
        clearTimeout(timer)
        resolve(value)
      },
    })
  })
  return { token, result }
}

async function getPendingVerification(key, cookie) {
  const current = state().active.get(key)
  if (current) return { owner: false, ...(await current) }

  const creating = (async () => {
    const challenge = await createVerification(cookie)
    return waitForVerification(challenge)
  })()
  state().active.set(key, creating)

  try {
    const pending = await creating
    pending.result.then(
      () => state().active.delete(key),
      () => state().active.delete(key),
    )
    return { owner: true, ...pending }
  } catch (error) {
    state().active.delete(key)
    throw error
  }
}

async function sendPrivateLink(e, link) {
  const message = `米游社查询触发了安全验证，请在两分钟内完成：\n${link}`
  if (e?.bot?.pickFriend) return e.bot.pickFriend(e.user_id).sendMsg(message)
  return Bot.sendFriendMsg(e.self_id, e.user_id, message)
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

    const baseUrl = String(GsCfg.getConfig("mys", "set")?.captchaBaseUrl || "").replace(/\/$/, "")
    if (!baseUrl) {
      reject("未配置 captchaBaseUrl")
      return res
    }

    try {
      const cookieId = crypto.createHash("sha256").update(mysApi.cookie).digest("hex").slice(0, 16)
      const pending = await getPendingVerification(`${e.user_id}:${mysApi.uid}:${cookieId}`, mysApi.cookie)
      const link = `${baseUrl}${ROUTE_PREFIX}${pending.token}`
      if (pending.owner) {
        await sendPrivateLink(e, link)
        if (e.isGroup) await e.reply("米游社需要安全验证，链接已发送至私聊。")
      }
      const solved = await pending.result
      return await mysApi.getData(type, {
        ...(data || {}),
        headers: {
          ...(data?.headers || {}),
          "x-rpc-challenge": solved.geetest_challenge,
          "x-rpc-validate": solved.geetest_validate,
          "x-rpc-seccode": solved.geetest_seccode,
        },
      })
    } catch (error) {
      logger.warn(`[米游社验证码] ${error.message}`)
      return res
    }
  }
}
