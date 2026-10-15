// scopeguard-worker — Sanctions Scope Monitoring
// v0.1.0 — 2026-10-15

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

function genId() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

async function checkSanctions(env, query) {
  const url = `https://compliance-engine/check/sanctions?q=${encodeURIComponent(query)}&threshold=0.85&limit=5`;
  const res = await env.COMPLIANCE.fetch(new Request(url));
  if (!res.ok) return { error: `compliance-engine HTTP ${res.status}` };
  return await res.json();
}

async function listScopeIds(env) {
  const list = await env.SCOPE_KV.list({ prefix: "scope:" });
  return (list.keys || []).map(k => k.name.replace("scope:", ""));
}

async function sendWebhook(webhook_url, payload) {
  try {
    const res = await fetch(webhook_url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

async function runAllScopes(env) {
  const ids = await listScopeIds(env);
  const results = [];
  let fired = 0;
  let changed = 0;

  for (const id of ids) {
    const raw = await env.SCOPE_KV.get(`scope:${id}`);
    if (!raw) continue;
    const scope = JSON.parse(raw);

    const checkResult = await checkSanctions(env, scope.query);
    const currentMatches = checkResult.total_matches || 0;
    const currentStatus = checkResult.status || "UNKNOWN";

    const prevMatches = scope.last_match_count || 0;
    const hasChanged = currentMatches !== prevMatches;

    let webhook_result = null;
    if (hasChanged && currentMatches > 0) {
      webhook_result = await sendWebhook(scope.webhook_url, {
        event: "scope_change",
        scope_id: id,
        query: scope.query,
        previous_match_count: prevMatches,
        current_match_count: currentMatches,
        status: currentStatus,
        matches: checkResult.results || [],
        checked_at: new Date().toISOString(),
      });
      if (webhook_result && webhook_result.ok) fired++;
      changed++;
    }

    scope.last_check = new Date().toISOString();
    scope.last_match_count = currentMatches;
    scope.last_status = currentStatus;
    await env.SCOPE_KV.put(`scope:${id}`, JSON.stringify(scope));

    results.push({
      id,
      query: scope.query,
      status: currentStatus,
      matches: currentMatches,
      previous_matches: prevMatches,
      changed: hasChanged,
      webhook: webhook_result,
    });
  }

  return { checked: ids.length, changed, webhooks_fired: fired, results };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    try {
      if (path === "/health" || path === "/") {
        const count = (await listScopeIds(env)).length;
        return json({
          status: "healthy",
          service: "scopeguard-worker",
          version: "0.1.0",
          scopes_count: count,
          endpoints: [
            "GET    /health",
            "POST   /scope              { query, webhook_url }",
            "GET    /scope/:id",
            "GET    /scopes             list all",
            "DELETE /scope/:id",
            "POST   /check              { query }",
            "POST   /cron               check all scopes & fire webhooks",
          ],
          timestamp: new Date().toISOString(),
        });
      }

      if (path === "/scope" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const query = String(body.query || "").trim();
        const webhook_url = String(body.webhook_url || "").trim();

        if (!query || query.length < 2) {
          return json({ error: "Missing or too short 'query'" }, 400);
        }
        if (!webhook_url || !/^https?:\/\//.test(webhook_url)) {
          return json({ error: "Missing or invalid 'webhook_url'" }, 400);
        }

        const id = genId();
        const scope = {
          id,
          query,
          webhook_url,
          created_at: new Date().toISOString(),
          last_check: null,
          last_match_count: null,
          last_status: null,
        };
        await env.SCOPE_KV.put(`scope:${id}`, JSON.stringify(scope));
        return json({ ok: true, scope });
      }

      if (path === "/scopes" && request.method === "GET") {
        const ids = await listScopeIds(env);
        const scopes = [];
        for (const id of ids) {
          const raw = await env.SCOPE_KV.get(`scope:${id}`);
          if (raw) scopes.push(JSON.parse(raw));
        }
        scopes.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
        return json({ ok: true, count: scopes.length, scopes });
      }

      if (path.startsWith("/scope/") && request.method === "GET") {
        const id = path.slice("/scope/".length);
        if (!id) return json({ error: "Missing id" }, 400);
        const raw = await env.SCOPE_KV.get(`scope:${id}`);
        if (!raw) return json({ error: "Not found", id }, 404);
        return json({ ok: true, scope: JSON.parse(raw) });
      }

      if (path.startsWith("/scope/") && request.method === "DELETE") {
        const id = path.slice("/scope/".length);
        if (!id) return json({ error: "Missing id" }, 400);
        const existing = await env.SCOPE_KV.get(`scope:${id}`);
        if (!existing) return json({ error: "Not found", id }, 404);
        await env.SCOPE_KV.delete(`scope:${id}`);
        return json({ ok: true, deleted: id });
      }

      if (path === "/check" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const query = String(body.query || "").trim();
        if (!query || query.length < 2) {
          return json({ error: "Missing or too short 'query'" }, 400);
        }
        const result = await checkSanctions(env, query);
        return json({ ok: true, query, result });
      }

      if (path === "/cron" && (request.method === "POST" || request.method === "GET")) {
        const result = await runAllScopes(env);
        return json({
          ok: true,
          checked: result.checked,
          changed: result.changed,
          webhooks_fired: result.webhooks_fired,
          results: result.results,
          timestamp: new Date().toISOString(),
        });
      }

      return json({ error: "Not found", path }, 404);
    } catch (err) {
      return json({ error: "Internal error", message: String(err) }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runAllScopes(env).catch(() => {}));
  },
};