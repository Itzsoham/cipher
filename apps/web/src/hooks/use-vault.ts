"use client";

import { useContext } from "react";
import { VaultContext } from "../contexts/vault-context";

export function useVault() {
  const context = useContext(VaultContext);
  if (!context) {
    throw new Error("useVault must be used within a VaultProvider");
  }
  return context;
}
