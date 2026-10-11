import { toast } from "sonner"

let pendingClearTimer: ReturnType<typeof setTimeout> | null = null
let activeToastId: string | number | null = null

export interface CopyToClipboardOptions {
  clearAfterMs?: number
  label?: string
}

/**
 * Copies a secret to the clipboard and arms an auto-clear countdown.
 *
 * Implements strict four-case feedback on expiry:
 *  1. Document unfocused -> show "Clipboard not cleared — tab was not focused", skip clear.
 *  2. Document focused, readText matches -> writeText(""), show "Clipboard cleared".
 *  3. Document focused, readText differs -> show "Clipboard not cleared — you copied something else", skip clear.
 *  4. Document focused, readText blocked -> show "Clipboard not cleared — permission denied", skip clear.
 */
export async function copyToClipboard(
  value: string,
  options: CopyToClipboardOptions = {}
): Promise<boolean> {
  if (typeof window === "undefined" || !navigator.clipboard) {
    toast.error("Clipboard API is not available")
    return false
  }

  // Cancel any existing pending clipboard clear timer and dismiss its toast
  clearPendingClipboardTimer()

  try {
    await navigator.clipboard.writeText(value)
  } catch {
    toast.error("Failed to copy to clipboard")
    return false
  }

  const durationMs = options.clearAfterMs ?? 30_000
  const durationSec = Math.round(durationMs / 1000)
  const itemLabel = options.label ? ` (${options.label})` : ""

  activeToastId = toast.info(
    `Copied${itemLabel}. Clipboard will be cleared in ${durationSec} seconds — this will overwrite whatever you copy next.`,
    {
      duration: durationMs,
    }
  )

  pendingClearTimer = setTimeout(async () => {
    pendingClearTimer = null
    if (activeToastId !== null) {
      toast.dismiss(activeToastId)
      activeToastId = null
    }

    // 1. Check if document has focus
    if (typeof document !== "undefined" && !document.hasFocus()) {
      toast.warning("Clipboard not cleared — tab was not focused")
      return
    }

    // 2. Try reading clipboard to verify content matches
    let currentClipText: string | null = null
    try {
      currentClipText = await navigator.clipboard.readText()
    } catch {
      // Permission denied or blocked
      toast.warning("Clipboard not cleared — permission denied")
      return
    }

    if (currentClipText === value) {
      try {
        await navigator.clipboard.writeText("")
        toast.success("Clipboard cleared")
      } catch {
        toast.warning("Failed to clear clipboard")
      }
    } else {
      toast.info("Clipboard not cleared — you copied something else")
    }
  }, durationMs)

  return true
}

/**
 * Cancels any active clipboard clearing timer and dismisses active countdown toast.
 */
export function clearPendingClipboardTimer(): void {
  if (pendingClearTimer) {
    clearTimeout(pendingClearTimer)
    pendingClearTimer = null
  }
  if (activeToastId !== null) {
    toast.dismiss(activeToastId)
    activeToastId = null
  }
}

