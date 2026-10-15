import { Container, getContainer } from '@cloudflare/containers';

export { ContainerProxy } from '@cloudflare/containers';

interface Env {
  ADMIN_BACKEND: DurableObjectNamespace<AdminBackend>;
  CLOUDFLARE_ACCOUNT_ID: string;
  CLOUDFLARE_DATABASE_ID: string;
  D1_API_TOKEN: string;
  JWT_SECRET: string;
  // "true" = API switched off (set by prket_alandlos_infra's power.yml)
  API_DISABLED?: string;
}

const ENV_FINGERPRINT_KEY = 'envFingerprint';

async function fingerprint(vars: Record<string, string> | undefined): Promise<string> {
  const json = JSON.stringify(Object.entries(vars ?? {}).sort(([a], [b]) => a.localeCompare(b)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(json));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The admin (auth) backend container (dist/index.js on port 5001). Serves /auth/* for the
 * admin frontend, and /auth/validate for the main backend's token checks.
 * A running container keeps the env vars it was started with, so new Worker secrets (D1 token,
 * JWT secret) would never reach it while it stays warm. It records a hash of its env on start;
 * the first request after a deploy restarts it if that env has changed.
 */
export class AdminBackend extends Container<Env> {
  defaultPort = 5001;
  sleepAfter = '15m';
  enableInternet = true; // D1 REST API

  private envChecked?: Promise<void>;

  constructor(ctx: DurableObjectState<{}>, env: Env) {
    super(ctx, env);
    this.envVars = {
      NODE_ENV: 'production',
      PORT: String(this.defaultPort),
      CLOUDFLARE_ACCOUNT_ID: env.CLOUDFLARE_ACCOUNT_ID,
      CLOUDFLARE_DATABASE_ID: env.CLOUDFLARE_DATABASE_ID,
      CLOUDFLARE_API_TOKEN: env.D1_API_TOKEN,
      JWT_SECRET: env.JWT_SECRET,
    };
  }

  override async onStart(): Promise<void> {
    await this.ctx.storage.put(ENV_FINGERPRINT_KEY, await fingerprint(this.envVars));
  }

  override async fetch(request: Request): Promise<Response> {
    // Env only changes with a new Worker version, which gets a fresh Durable Object instance
    this.envChecked ??= (async () => {
      if (!this.ctx.container?.running) return;
      const started = await this.ctx.storage.get<string>(ENV_FINGERPRINT_KEY);
      if (started === (await fingerprint(this.envVars))) return;
      console.log('Container env changed since it started, restarting it');
      await this.destroy();
    })();
    await this.envChecked;
    return super.fetch(request);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Switched off: never wake the container. A running one gets no traffic and
    // shuts down gracefully once sleepAfter elapses; nothing is deleted.
    if (env.API_DISABLED === 'true') {
      return Response.json({ error: 'Service temporarily unavailable' }, { status: 503, headers: { 'Retry-After': '3600' } });
    }
    return getContainer(env.ADMIN_BACKEND).fetch(request);
  },
} satisfies ExportedHandler<Env>;
