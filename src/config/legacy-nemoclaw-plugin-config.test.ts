import { describe, expect, it } from "vitest";
import { normalizeLegacyNemoclawPluginConfig } from "./legacy-nemoclaw-plugin-config.js";

describe("normalizeLegacyNemoclawPluginConfig", () => {
  it("moves flat plugins.nemoclaw fields into plugins.entries.nemoclaw.config", () => {
    const raw = {
      plugins: {
        enabled: true,
        nemoclaw: {
          agentOutputLambdaArn: "arn:aws:lambda:us-east-1:123:function:reply",
          chatId: "999",
        },
      },
    };
    const out = normalizeLegacyNemoclawPluginConfig(raw);
    expect(out).toEqual({
      plugins: {
        enabled: true,
        entries: {
          nemoclaw: {
            config: {
              agentOutputLambdaArn: "arn:aws:lambda:us-east-1:123:function:reply",
              chatId: "999",
            },
          },
        },
      },
    });
  });

  it("merges with existing plugins.entries.nemoclaw", () => {
    const raw = {
      plugins: {
        entries: {
          nemoclaw: {
            enabled: true,
            config: { blueprintVersion: "0.1.0" },
          },
        },
        nemoclaw: {
          chatId: "111",
        },
      },
    };
    const out = normalizeLegacyNemoclawPluginConfig(raw);
    expect(
      (out as { plugins: { entries: { nemoclaw: { config: Record<string, string> } } } }).plugins
        .entries.nemoclaw,
    ).toEqual({
      enabled: true,
      config: {
        blueprintVersion: "0.1.0",
        chatId: "111",
      },
    });
  });

  it("is a no-op when plugins.nemoclaw is absent", () => {
    const raw = { plugins: { entries: { nemoclaw: { config: { x: 1 } } } } };
    expect(normalizeLegacyNemoclawPluginConfig(raw)).toEqual(raw);
  });
});
