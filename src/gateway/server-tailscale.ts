import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { resolveGatewayLockDir } from "../config/paths.js";
import {
  disableTailscaleFunnel,
  disableTailscaleServe,
  enableTailscaleFunnel,
  enableTailscaleServe,
  getTailnetHostname,
} from "../infra/tailscale.js";

type GatewayTailscaleMode = "off" | "serve" | "funnel";

type TailscaleExposureOwnerRecord = {
  token: string;
  mode: Exclude<GatewayTailscaleMode, "off">;
  port: number;
  pid: number;
  claimedAt: string;
};

type TailscaleExposureOwnerStore = {
  claim(
    mode: Exclude<GatewayTailscaleMode, "off">,
    port: number,
  ): Promise<TailscaleExposureOwnerRecord>;
  isCurrentOwner(token: string): Promise<boolean>;
  clearIfCurrentOwner(token: string): Promise<void>;
};

function createTailscaleExposureOwnerStore(): TailscaleExposureOwnerStore {
  const ownerFilePath = path.join(resolveGatewayLockDir(), "tailscale-exposure-owner.json");

  async function readOwner(): Promise<TailscaleExposureOwnerRecord | null> {
    try {
      const raw = await fs.readFile(ownerFilePath, "utf8");
      const parsed = JSON.parse(raw);
      if (
        parsed &&
        typeof parsed === "object" &&
        typeof parsed.token === "string" &&
        typeof parsed.mode === "string" &&
        typeof parsed.port === "number" &&
        typeof parsed.pid === "number" &&
        typeof parsed.claimedAt === "string"
      ) {
        return parsed as TailscaleExposureOwnerRecord;
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException | undefined)?.code !== "ENOENT") {
        // Ignore malformed or unreadable ownership state and continue.
      }
    }
    return null;
  }

  return {
    async claim(mode, port) {
      const record: TailscaleExposureOwnerRecord = {
        token: randomUUID(),
        mode,
        port,
        pid: process.pid,
        claimedAt: new Date().toISOString(),
      };
      await fs.mkdir(path.dirname(ownerFilePath), { recursive: true });
      await fs.writeFile(ownerFilePath, JSON.stringify(record), "utf8");
      return record;
    },
    async isCurrentOwner(token) {
      const current = await readOwner();
      return current?.token === token;
    },
    async clearIfCurrentOwner(token) {
      if (!(await this.isCurrentOwner(token))) {
        return;
      }
      try {
        await fs.unlink(ownerFilePath);
      } catch (err) {
        if ((err as NodeJS.ErrnoException | undefined)?.code !== "ENOENT") {
          throw err;
        }
      }
    },
  };
}

export async function startGatewayTailscaleExposure(params: {
  tailscaleMode: GatewayTailscaleMode;
  resetOnExit?: boolean;
  port: number;
  controlUiBasePath?: string;
  logTailscale: { info: (msg: string) => void; warn: (msg: string) => void };
  ownerStore?: TailscaleExposureOwnerStore;
}): Promise<(() => Promise<void>) | null> {
  if (params.tailscaleMode === "off") {
    return null;
  }

  const ownerStore = params.ownerStore ?? createTailscaleExposureOwnerStore();
  const owner = await ownerStore.claim(params.tailscaleMode, params.port);

  try {
    if (params.tailscaleMode === "serve") {
      await enableTailscaleServe(params.port);
    } else {
      await enableTailscaleFunnel(params.port);
    }
    const host = await getTailnetHostname().catch(() => null);
    if (host) {
      const uiPath = params.controlUiBasePath ? `${params.controlUiBasePath}/` : "/";
      params.logTailscale.info(
        `${params.tailscaleMode} enabled: https://${host}${uiPath} (WS via wss://${host})`,
      );
    } else {
      params.logTailscale.info(`${params.tailscaleMode} enabled`);
    }
  } catch (err) {
    await ownerStore.clearIfCurrentOwner(owner.token).catch(() => {});
    params.logTailscale.warn(
      `${params.tailscaleMode} failed: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!params.resetOnExit) {
    return null;
  }

  return async () => {
    try {
      if (!(await ownerStore.isCurrentOwner(owner.token))) {
        params.logTailscale.info(
          `${params.tailscaleMode} cleanup skipped: newer gateway owns Tailscale exposure`,
        );
        return;
      }
      if (params.tailscaleMode === "serve") {
        await disableTailscaleServe();
      } else {
        await disableTailscaleFunnel();
      }
      await ownerStore.clearIfCurrentOwner(owner.token);
    } catch (err) {
      params.logTailscale.warn(
        `${params.tailscaleMode} cleanup failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };
}
