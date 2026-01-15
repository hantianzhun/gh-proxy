'use strict'

/** ================= 基础配置 ================= */

const PREFIX = '/'
const Config = { jsdelivr: 0 }
const whiteList = []

/** 限流配置 */
const RATE_LIMIT = {
  window: 60, // 秒
  max: 30     // 次
}

/** ================= 正则 ================= */

const exp1 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:releases|archive)\/.*$/i
const exp2 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:blob|raw)\/.*$/i
const exp3 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/(?:info|git-).*$/i
const exp4 = /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+?\/.+$/i
const exp5 = /^(?:https?:\/\/)?gist\.(?:githubusercontent|github)\.com\/.+?\/.+?\/.+$/i
const exp6 = /^(?:https?:\/\/)?github\.com\/.+?\/.+?\/tags.*$/i

const PREFLIGHT_INIT = {
  status: 204,
  headers: {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,PUT,PATCH,TRACE,DELETE,HEAD,OPTIONS',
    'access-control-max-age': '1728000',
  },
}

/** ================= Worker 入口 ================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url)

    /** 首页 & 静态文件（不走限流） */
    if (
      url.pathname === '/' ||
      url.pathname === '/index.html' ||
      url.pathname === '/github.html'
    ) {
      return env.ASSETS.fetch(
        new Request(new URL('/github.html', url), request)
      )
    }


    /** ?q= 参数 */
    const q = url.searchParams.get('q')
    if (q) {
      return Response.redirect(url.origin + PREFIX + q, 301)
    }

    /** GitHub 代理请求 → 限流 */
    const limited = await rateLimit(request)
    if (limited) return limited

    /** 解析路径（保持你原来的写法） */
    let path = url.href
      .slice(url.origin.length + PREFIX.length)
      .replace(/^https?:\/+/, 'https://')

    if (
      path.search(exp1) === 0 ||
      path.search(exp5) === 0 ||
      path.search(exp6) === 0 ||
      path.search(exp3) === 0
    ) {
      return httpHandler(request, path)
    }

    if (path.search(exp2) === 0) {
      if (Config.jsdelivr) {
        const newUrl = path
          .replace('/blob/', '@')
          .replace(/^(?:https?:\/\/)?github\.com/, 'https://cdn.jsdelivr.net/gh')
        return Response.redirect(newUrl, 302)
      } else {
        return httpHandler(request, path.replace('/blob/', '/raw/'))
      }
    }

    if (path.search(exp4) === 0) {
      if (Config.jsdelivr) {
        const newUrl = path
          .replace(/(?<=com\/.+?\/.+?)\/(.+?\/)/, '@$1')
          .replace(
            /^(?:https?:\/\/)?raw\.(?:githubusercontent|github)\.com/,
            'https://cdn.jsdelivr.net/gh'
          )
        return Response.redirect(newUrl, 302)
      } else {
        return httpHandler(request, path)
      }
    }

    return new Response('Not Found', { status: 404 })
  }
}

/** ================= 限流实现 ================= */

async function rateLimit(request) {
  const ip =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For') ||
    'unknown'

  const key = `https://rate.limit/${ip}`
  const cache = caches.default

  let res = await cache.match(key)
  let count = res ? Number(await res.text()) : 0

  if (count >= RATE_LIMIT.max) {
    return new Response(
      `Too Many Requests\nLimit: ${RATE_LIMIT.max}/${RATE_LIMIT.window}s`,
      {
        status: 429,
        headers: {
          'content-type': 'text/plain',
          'retry-after': String(RATE_LIMIT.window)
        }
      }
    )
  }

  await cache.put(
    key,
    new Response(String(count + 1), {
      headers: {
        'cache-control': `max-age=${RATE_LIMIT.window}`
      }
    })
  )

  return null
}

/** ================= 代理核心（原逻辑） ================= */

function httpHandler(req, pathname) {
  if (
    req.method === 'OPTIONS' &&
    req.headers.has('access-control-request-headers')
  ) {
    return new Response(null, PREFLIGHT_INIT)
  }

  let urlStr = pathname
  let allow = !whiteList.length || whiteList.some(v => urlStr.includes(v))
  if (!allow) return new Response('blocked', { status: 403 })

  if (!/^https?:\/\//.test(urlStr)) {
    urlStr = 'https://' + urlStr
  }

  return proxy(new URL(urlStr), {
    method: req.method,
    headers: req.headers,
    redirect: 'manual',
    body: req.body
  })
}

function checkUrl(u) {
  return [exp1, exp2, exp3, exp4, exp5, exp6].some(i => u.search(i) === 0)
}

async function proxy(urlObj, reqInit) {
  const res = await fetch(urlObj.href, reqInit)
  const headers = new Headers(res.headers)

  if (headers.has('location')) {
    const loc = headers.get('location')
    if (checkUrl(loc)) {
      headers.set('location', PREFIX + loc)
    } else {
      reqInit.redirect = 'follow'
      return proxy(new URL(loc), reqInit)
    }
  }

  headers.set('access-control-allow-origin', '*')
  headers.set('access-control-expose-headers', '*')

  headers.delete('content-security-policy')
  headers.delete('content-security-policy-report-only')
  headers.delete('clear-site-data')

  return new Response(res.body, {
    status: res.status,
    headers
  })
}
