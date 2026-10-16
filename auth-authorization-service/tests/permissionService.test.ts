import { describe, expect, it } from "vitest";
import { resourceMatches } from "../src/services/permissionService.js";

describe("Wildcard resource matching", () => {
  it("matches a wallet resource", () => {
    expect(
      resourceMatches("wallets/*", "wallets/wallet-789")
    ).toBe(true);
  });

  it("does not match nested resources with a single-level wildcard", () => {
    expect(
      resourceMatches("wallets/*", "wallets/wallet-789/transactions")
    ).toBe(false);
  });

  it("matches nested resources with an explicit wildcard pattern", () => {
    expect(
      resourceMatches(
        "wallets/*/transactions/*",
        "wallets/wallet-789/transactions/tx-123"
      )
    ).toBe(true);
  });

  it("does not match a different collection", () => {
    expect(
      resourceMatches("wallets/*", "accounts/account-123")
    ).toBe(false);
  });
});
