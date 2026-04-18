import { describe, it, expect } from "vitest";
import { b64Encode, b64Decode, constantTimeEqual, randomBytes, bytesToHex } from "../primitives";

describe("Crypto Primitives", () => {
  describe("Base64url Encoding/Decoding", () => {
    it("should correctly encode and decode a Uint8Array", () => {
      const data = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const encoded = b64Encode(data);
      expect(encoded).toBe("SGVsbG8");
      
      const decoded = b64Decode(encoded);
      expect(decoded).toEqual(data);
    });

    it("should handle empty buffers", () => {
      const data = new Uint8Array(0);
      const encoded = b64Encode(data);
      expect(encoded).toBe("");
      expect(b64Decode(encoded)).toEqual(new Uint8Array(0));
    });

    it("should handle Base64url specific characters (+, / -> -, _)", () => {
      // Binary [251, 255] encodes to "+/8=" in standard base64
      // Should be "-_8" in b64url
      const data = new Uint8Array([251, 255]);
      const encoded = b64Encode(data);
      expect(encoded).toBe("-_8");
      expect(b64Decode(encoded)).toEqual(data);
    });
  });

  describe("constantTimeEqual", () => {
    it("should return true for identical buffers", () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3]);
      expect(constantTimeEqual(a, b)).toBe(true);
    });

    it("should return false for different lengths", () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2]);
      expect(constantTimeEqual(a, b)).toBe(false);
    });

    it("should return false for same length but different content", () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);
      expect(constantTimeEqual(a, b)).toBe(false);
    });
  });

  describe("Utility functions", () => {
    it("randomBytes should return correct length", () => {
      const bytes = randomBytes(32);
      expect(bytes.length).toBe(32);
      expect(bytes).toBeInstanceOf(Uint8Array);
    });

    it("bytesToHex should convert correctly", () => {
      const bytes = new Uint8Array([0x01, 0x02, 0x0a, 0xff]);
      expect(bytesToHex(bytes)).toBe("01020aff");
    });
  });
});
