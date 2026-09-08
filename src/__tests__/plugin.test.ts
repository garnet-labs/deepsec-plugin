import { describe, expect, it } from "vitest";
import garnetPlugin from "../index.js";

function captureProgram() {
  const commands: string[] = [];
  const command = {
    description: () => command,
    requiredOption: () => command,
    option: () => command,
    action: () => command,
  };
  return {
    commands,
    program: {
      command(name: string) {
        commands.push(name);
        return command;
      },
    },
  };
}

describe("@garnet-org/deepsec-plugin", () => {
  it("fills the command slot with a stable plugin name", () => {
    const plugin = garnetPlugin();
    expect(plugin.name).toBe("@garnet-org/deepsec-plugin");
    expect(typeof plugin.commands).toBe("function");
  });

  it("registers garnet-correlate without a token in the environment", () => {
    const previous = process.env.GARNET_API_TOKEN;
    delete process.env.GARNET_API_TOKEN;
    try {
      const { program, commands } = captureProgram();
      garnetPlugin().commands?.(program);
      expect(commands).toEqual(["garnet-correlate"]);
    } finally {
      if (previous === undefined) delete process.env.GARNET_API_TOKEN;
      else process.env.GARNET_API_TOKEN = previous;
    }
  });

  it("contributes no matchers, ownership, people, or executor slot", () => {
    const plugin = garnetPlugin({ apiToken: "test" });
    expect(plugin.matchers).toBeUndefined();
    expect(plugin.ownership).toBeUndefined();
    expect(plugin.people).toBeUndefined();
    expect(plugin.executor).toBeUndefined();
  });

  it("adds the notifier only with full GitHub pull request context", () => {
    const env = {
      GITHUB_TOKEN: process.env.GITHUB_TOKEN,
      GITHUB_REF: process.env.GITHUB_REF,
      GITHUB_RUN_ID: process.env.GITHUB_RUN_ID,
      GITHUB_REPOSITORY: process.env.GITHUB_REPOSITORY,
    };
    try {
      process.env.GITHUB_TOKEN = "gh-test";
      process.env.GITHUB_REF = "refs/pull/7/merge";
      process.env.GITHUB_RUN_ID = "123";
      process.env.GITHUB_REPOSITORY = "garnet-labs/deepsec-plugin";
      expect(garnetPlugin({ apiToken: "test" }).notifiers).toHaveLength(1);

      delete process.env.GITHUB_TOKEN;
      expect(garnetPlugin({ apiToken: "test" }).notifiers).toBeUndefined();
    } finally {
      for (const [key, value] of Object.entries(env)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });
});
