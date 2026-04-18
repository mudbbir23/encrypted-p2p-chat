import { describe, it, expect } from "vitest";
import { x25519 } from "@noble/curves/ed25519";
import { x3dhSender, x3dhReceiver, X3DHBundle } from "../x3dh";
import { b64Encode, b64Decode } from "../primitives";

describe("X3DH Key Agreement", () => {
  it("Alice and Bob should derive the same shared key", async () => {
    // 1. Setup Bob's identity and prekeys
    const bobIdentityPriv = x25519.utils.randomPrivateKey();
    const bobIdentityPub = x25519.getPublicKey(bobIdentityPriv);
    
    const bobSPKPriv = x25519.utils.randomPrivateKey();
    const bobSPKPub = x25519.getPublicKey(bobSPKPriv);
    
    const bobOPKPriv = x25519.utils.randomPrivateKey();
    const bobOPKPub = x25519.getPublicKey(bobOPKPriv);

    // 2. Bob's bundle as if received from the server
    const bobBundle: X3DHBundle = {
      identity_key_x25519: b64Encode(bobIdentityPub),
      identity_key_ed25519: "dummy_ed25519", // Not used in shared key derivation
      signed_prekey: b64Encode(bobSPKPub),
      signed_prekey_signature: "dummy_signature",
      one_time_prekey: b64Encode(bobOPKPub),
      one_time_prekey_id: 1,
    };

    // 3. Alice initiates X3DH
    const aliceIdentityPriv = x25519.utils.randomPrivateKey();
    const aliceIdentityPub = x25519.getPublicKey(aliceIdentityPriv);

    const aliceResult = await x3dhSender(aliceIdentityPriv, aliceIdentityPub, bobBundle);
    
    // 4. Bob receives Alice's initialization
    const bobResult = await x3dhReceiver(
      bobIdentityPriv,
      bobIdentityPub,
      bobSPKPriv,
      bobOPKPriv, // Bob uses the private key corresponding to the OPK Alice used
      b64Decode(aliceResult.ephemeralPublicKey),
      aliceIdentityPub
    );

    // 5. Assertions
    expect(aliceResult.sharedKey).toEqual(bobResult.sharedKey);
    expect(aliceResult.associatedData).toEqual(bobResult.associatedData);
    expect(aliceResult.usedOneTimePrekey).toBe(true);
  });

  it("should work correctly without a One-Time Prekey (DH1-DH3 only)", async () => {
    const bobIdentityPriv = x25519.utils.randomPrivateKey();
    const bobIdentityPub = x25519.getPublicKey(bobIdentityPriv);
    const bobSPKPriv = x25519.utils.randomPrivateKey();
    const bobSPKPub = x25519.getPublicKey(bobSPKPriv);

    const bobBundle: X3DHBundle = {
      identity_key_x25519: b64Encode(bobIdentityPub),
      identity_key_ed25519: "dummy_ed25519",
      signed_prekey: b64Encode(bobSPKPub),
      signed_prekey_signature: "dummy_signature",
      one_time_prekey: null, // NO OPK
    };

    const aliceIdentityPriv = x25519.utils.randomPrivateKey();
    const aliceIdentityPub = x25519.getPublicKey(aliceIdentityPriv);

    const aliceResult = await x3dhSender(aliceIdentityPriv, aliceIdentityPub, bobBundle);
    
    const bobResult = await x3dhReceiver(
      bobIdentityPriv,
      bobIdentityPub,
      bobSPKPriv,
      null, // No OPK priv
      b64Decode(aliceResult.ephemeralPublicKey),
      aliceIdentityPub
    );

    expect(aliceResult.sharedKey).toEqual(bobResult.sharedKey);
    expect(aliceResult.usedOneTimePrekey).toBe(false);
  });
});
