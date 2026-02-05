import { describe, it, expect } from "vitest";
import {
  parseSession,
  createSession,
  serializeSession,
} from "../src/session.js";

describe("Session parsing", () => {
  it("should parse valid session YAML", () => {
    const yaml = `
name: test-session
recordedAt: "2026-02-05T09:00:00Z"
browser: chromium
viewport:
  width: 1280
  height: 720
startUrl: https://example.com
steps:
  - id: step-1
    type: navigate
    url: https://example.com
    timestamp: 0
  - id: step-2
    type: input
    selector: "#input"
    value: "test"
    timestamp: 100
  - id: step-3
    type: click
    selector: "#submit"
    timestamp: 200
`;
    const session = parseSession(yaml);
    expect(session.name).toBe("test-session");
    expect(session.steps).toHaveLength(3);
  });

  it("should parse session with payload placeholder", () => {
    const yaml = `
name: payload-test
recordedAt: "2026-02-05T09:00:00Z"
viewport:
  width: 1280
  height: 720
startUrl: https://example.com
steps:
  - id: step-1
    type: input
    selector: "#search"
    value: "{{PAYLOAD}}"
    timestamp: 0
`;
    const session = parseSession(yaml);
    expect(session.steps[0].type).toBe("input");
    if (session.steps[0].type === "input") {
      expect(session.steps[0].value).toBe("{{PAYLOAD}}");
    }
  });

  it("should throw on invalid session YAML", () => {
    const invalidYaml = `
name: missing-fields
`;
    expect(() => parseSession(invalidYaml)).toThrow();
  });

  it("should validate step types", () => {
    const yaml = `
name: step-types-test
recordedAt: "2026-02-05T09:00:00Z"
viewport:
  width: 1280
  height: 720
startUrl: https://example.com
steps:
  - id: s1
    type: navigate
    url: https://example.com
    timestamp: 0
  - id: s2
    type: click
    selector: button
    timestamp: 100
  - id: s3
    type: input
    selector: input
    value: text
    timestamp: 200
  - id: s4
    type: wait
    duration: 1000
    timestamp: 300
`;
    const session = parseSession(yaml);
    expect(session.steps[0].type).toBe("navigate");
    expect(session.steps[1].type).toBe("click");
    expect(session.steps[2].type).toBe("input");
    expect(session.steps[3].type).toBe("wait");
  });
});

describe("Session creation", () => {
  it("should create session with defaults", () => {
    const session = createSession({
      name: "new-session",
      startUrl: "https://example.com",
    });
    expect(session.name).toBe("new-session");
    expect(session.browser).toBe("chromium");
    expect(session.viewport).toEqual({ width: 1280, height: 720 });
    expect(session.steps).toEqual([]);
  });

  it("should create session with custom options", () => {
    const session = createSession({
      name: "custom-session",
      startUrl: "https://example.com",
      browser: "firefox",
      viewport: { width: 1920, height: 1080 },
    });
    expect(session.browser).toBe("firefox");
    expect(session.viewport).toEqual({ width: 1920, height: 1080 });
  });
});

describe("Session serialization", () => {
  it("should serialize and parse session roundtrip", () => {
    const original = createSession({
      name: "roundtrip-test",
      startUrl: "https://example.com",
    });
    const yaml = serializeSession(original);
    const parsed = parseSession(yaml);
    expect(parsed.name).toBe(original.name);
    expect(parsed.startUrl).toBe(original.startUrl);
  });
});
