/**
 * Auth Module Tests
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  encrypt,
  decrypt,
  encryptCredentials,
  decryptCredentials,
  encryptStorageState,
  decryptStorageState,
  getPassphrase,
} from "./auth";
import type { FormCredentials, HeaderCredentials } from "./auth";

describe("Auth Module", () => {
  describe("encrypt / decrypt", () => {
    it("should encrypt and decrypt a string", () => {
      const plaintext = "hello world";
      const passphrase = "my-secret-key";

      const encrypted = encrypt(plaintext, passphrase);
      const decrypted = decrypt(encrypted, passphrase);

      expect(decrypted).toBe(plaintext);
    });

    it("should produce valid JSON output", () => {
      const encrypted = encrypt("test", "pass");
      const parsed = JSON.parse(encrypted);

      expect(parsed.version).toBe(1);
      expect(parsed.salt).toBeTruthy();
      expect(parsed.iv).toBeTruthy();
      expect(parsed.tag).toBeTruthy();
      expect(parsed.data).toBeTruthy();
      expect(parsed.iterations).toBe(100_000);
    });

    it("should produce different ciphertext for same input (random salt/iv)", () => {
      const plaintext = "same input";
      const passphrase = "same-key";

      const encrypted1 = encrypt(plaintext, passphrase);
      const encrypted2 = encrypt(plaintext, passphrase);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it("should fail with wrong passphrase", () => {
      const encrypted = encrypt("secret", "correct-key");

      expect(() => decrypt(encrypted, "wrong-key")).toThrow();
    });

    it("should fail with tampered data", () => {
      const encrypted = encrypt("secret", "key");
      const parsed = JSON.parse(encrypted);
      parsed.data = parsed.data.replace(/./g, "0"); // corrupt the data
      const tampered = JSON.stringify(parsed);

      expect(() => decrypt(tampered, "key")).toThrow();
    });

    it("should handle empty string", () => {
      const encrypted = encrypt("", "key");
      const decrypted = decrypt(encrypted, "key");
      expect(decrypted).toBe("");
    });

    it("should handle unicode content", () => {
      const plaintext = "hello 🔒 wörld 日本語";
      const encrypted = encrypt(plaintext, "key");
      const decrypted = decrypt(encrypted, "key");
      expect(decrypted).toBe(plaintext);
    });

    it("should handle large content", () => {
      const plaintext = "x".repeat(100_000);
      const encrypted = encrypt(plaintext, "key");
      const decrypted = decrypt(encrypted, "key");
      expect(decrypted).toBe(plaintext);
    });

    it("should reject unsupported version", () => {
      const encrypted = encrypt("test", "key");
      const parsed = JSON.parse(encrypted);
      parsed.version = 99;
      const modified = JSON.stringify(parsed);

      expect(() => decrypt(modified, "key")).toThrow(
        "Unsupported encryption version: 99",
      );
    });
  });

  describe("encryptCredentials / decryptCredentials", () => {
    it("should encrypt and decrypt form credentials", () => {
      const creds: FormCredentials = {
        type: "form",
        username: "admin",
        password: "password123",
      };

      const encrypted = encryptCredentials(creds, "key");
      const decrypted = decryptCredentials(encrypted, "key");

      expect(decrypted).toEqual(creds);
      expect(decrypted.type).toBe("form");
      if (decrypted.type === "form") {
        expect(decrypted.username).toBe("admin");
        expect(decrypted.password).toBe("password123");
      }
    });

    it("should preserve optional fields", () => {
      const creds: FormCredentials = {
        type: "form",
        username: "admin",
        password: "pass",
        loginUrl: "https://dvwa.local/login",
        userSelector: "#custom-user",
        passSelector: "#custom-pass",
      };

      const encrypted = encryptCredentials(creds, "key");
      const decrypted = decryptCredentials(encrypted, "key");

      expect(decrypted).toEqual(creds);
    });

    it("should support header credentials", () => {
      const creds: HeaderCredentials = {
        type: "header",
        headers: {
          Authorization: "Bearer abc123",
          "X-API-Key": "key456",
        },
      };

      const encrypted = encryptCredentials(creds, "key");
      const decrypted = decryptCredentials(encrypted, "key");

      expect(decrypted).toEqual(creds);
    });
  });

  describe("encryptStorageState / decryptStorageState", () => {
    it("should encrypt and decrypt storage state JSON", () => {
      const storageState = JSON.stringify({
        cookies: [{ name: "session", value: "abc123", domain: ".dvwa.local" }],
        origins: [],
      });

      const encrypted = encryptStorageState(storageState, "key");
      const decrypted = decryptStorageState(encrypted, "key");

      expect(decrypted).toBe(storageState);
      expect(JSON.parse(decrypted).cookies[0].name).toBe("session");
    });
  });

  describe("getPassphrase", () => {
    const originalEnv = process.env.VULCN_KEY;

    afterEach(() => {
      if (originalEnv !== undefined) {
        process.env.VULCN_KEY = originalEnv;
      } else {
        delete process.env.VULCN_KEY;
      }
    });

    it("should prefer interactive passphrase", () => {
      process.env.VULCN_KEY = "env-key";
      expect(getPassphrase("interactive-key")).toBe("interactive-key");
    });

    it("should fall back to env var", () => {
      process.env.VULCN_KEY = "env-key";
      expect(getPassphrase()).toBe("env-key");
    });

    it("should throw when no passphrase available", () => {
      delete process.env.VULCN_KEY;
      expect(() => getPassphrase()).toThrow("No passphrase provided");
    });
  });
});
