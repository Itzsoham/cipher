"use client"

import * as React from "react"
import { copyToClipboard } from "@/lib/vault/clipboard"
import {
  generatePassphrase,
  generatePassword,
} from "@/lib/vault/password-generator"
import { evaluatePasswordStrength } from "@/lib/vault/password-strength"
import { Button } from "@cipher/ui/components/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@cipher/ui/components/dialog"
import { Input } from "@cipher/ui/components/input"
import { Label } from "@cipher/ui/components/label"
import { Check, Copy, RefreshCw, Wand2 } from "lucide-react"

interface PasswordGeneratorDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSelectPassword?: (password: string) => void
}

export function PasswordGeneratorDialog({
  open,
  onOpenChange,
  onSelectPassword,
}: PasswordGeneratorDialogProps) {
  const [mode, setMode] = React.useState<"characters" | "passphrase">("characters")

  // Character mode settings
  const [length, setLength] = React.useState<number>(20)
  const [useUpper, setUseUpper] = React.useState<boolean>(true)
  const [useLower, setUseLower] = React.useState<boolean>(true)
  const [useNumbers, setUseNumbers] = React.useState<boolean>(true)
  const [useSymbols, setUseSymbols] = React.useState<boolean>(true)
  const [avoidAmbiguous, setAvoidAmbiguous] = React.useState<boolean>(true)

  // Passphrase mode settings
  const [wordCount, setWordCount] = React.useState<number>(6)
  const [separator, setSeparator] = React.useState<string>("-")
  const [capitalize, setCapitalize] = React.useState<boolean>(false)
  const [includeNumber, setIncludeNumber] = React.useState<boolean>(false)

  const [generatedPassword, setGeneratedPassword] = React.useState<string>(() =>
    generatePassword({ length: 20 })
  )
  const [hasCopied, setHasCopied] = React.useState<boolean>(false)

  const handleRegenerate = React.useCallback(() => {
    if (mode === "characters") {
      const pw = generatePassword({
        length,
        uppercase: useUpper,
        lowercase: useLower,
        numbers: useNumbers,
        symbols: useSymbols,
        avoidAmbiguous,
      })
      setGeneratedPassword(pw)
    } else {
      const pw = generatePassphrase({
        wordCount,
        separator,
        capitalize,
        includeNumber,
      })
      setGeneratedPassword(pw)
    }
  }, [
    mode,
    length,
    useUpper,
    useLower,
    useNumbers,
    useSymbols,
    avoidAmbiguous,
    wordCount,
    separator,
    capitalize,
    includeNumber,
  ])


  const strength = React.useMemo(() => {
    return evaluatePasswordStrength(generatedPassword)
  }, [generatedPassword])

  const handleCopy = async () => {
    const success = await copyToClipboard(generatedPassword, { label: "Generated Password" })
    if (success) {
      setHasCopied(true)
      setTimeout(() => setHasCopied(false), 2000)
    }
  }

  const handleApply = () => {
    if (onSelectPassword) {
      onSelectPassword(generatedPassword)
    }
    onOpenChange(false)
  }

  const strengthColor = [
    "bg-destructive",
    "bg-orange-500",
    "bg-yellow-500",
    "bg-emerald-500",
    "bg-emerald-600",
  ][strength.score] ?? "bg-muted"

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Wand2 className="size-5 text-primary" />
            Password Generator
          </DialogTitle>
          <DialogDescription>
            Cryptographically secure, unbiased generation using local WebCrypto entropy.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          {/* Mode Tabs */}
          <div className="flex rounded-lg bg-muted p-1 text-xs">
            <button
              type="button"
              className={`flex-1 rounded-md py-1.5 font-medium transition-colors ${
                mode === "characters" ? "bg-background text-foreground shadow-xs" : "text-muted-foreground"
              }`}
              onClick={() => setMode("characters")}
            >
              Random Characters
            </button>
            <button
              type="button"
              className={`flex-1 rounded-md py-1.5 font-medium transition-colors ${
                mode === "passphrase" ? "bg-background text-foreground shadow-xs" : "text-muted-foreground"
              }`}
              onClick={() => setMode("passphrase")}
            >
              Diceware Passphrase
            </button>
          </div>

          {/* Generated Result Display */}
          <div className="space-y-2">
            <div className="relative">
              <Input
                readOnly
                value={generatedPassword}
                spellCheck={false}
                autoComplete="off"
                className="font-mono text-base pr-20 select-all"
              />
              <div className="absolute right-1 top-1 flex items-center gap-1">
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  onClick={handleRegenerate}
                  title="Generate new"
                >
                  <RefreshCw className="size-4" />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  onClick={handleCopy}
                  title="Copy to clipboard"
                >
                  {hasCopied ? <Check className="size-4 text-emerald-500" /> : <Copy className="size-4" />}
                </Button>
              </div>
            </div>

            {/* Strength Meter Bar */}
            <div className="space-y-1">
              <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full transition-all duration-300 ${strengthColor}`}
                  style={{ width: `${Math.max(10, ((strength.score + 1) / 5) * 100)}%` }}
                />
              </div>
              <div className="flex justify-between text-[11px] text-muted-foreground">
                <span>Strength score: {strength.score} / 4</span>
                {strength.warning && <span className="text-destructive">{strength.warning}</span>}
              </div>
            </div>
          </div>

          {/* Controls */}
          {mode === "characters" ? (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="length-slider" className="text-xs">
                  Length: {length} characters
                </Label>
              </div>
              <input
                id="length-slider"
                type="range"
                min="8"
                max="64"
                value={length}
                onChange={(e) => setLength(parseInt(e.target.value, 10))}
                className="w-full accent-primary"
              />

              <div className="grid grid-cols-2 gap-2 pt-2 text-xs">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useUpper}
                    onChange={(e) => setUseUpper(e.target.checked)}
                    className="rounded accent-primary"
                  />
                  Uppercase (A-Z)
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useLower}
                    onChange={(e) => setUseLower(e.target.checked)}
                    className="rounded accent-primary"
                  />
                  Lowercase (a-z)
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useNumbers}
                    onChange={(e) => setUseNumbers(e.target.checked)}
                    className="rounded accent-primary"
                  />
                  Numbers (0-9)
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={useSymbols}
                    onChange={(e) => setUseSymbols(e.target.checked)}
                    className="rounded accent-primary"
                  />
                  Symbols (!@#$)
                </label>
                <label className="flex items-center gap-2 col-span-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={avoidAmbiguous}
                    onChange={(e) => setAvoidAmbiguous(e.target.checked)}
                    className="rounded accent-primary"
                  />
                  Avoid ambiguous characters (0, O, 1, l, I)
                </label>
              </div>
            </div>
          ) : (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="words-slider" className="text-xs">
                  Word count: {wordCount} words (~{wordCount * 10} bits entropy)
                </Label>
              </div>
              <input
                id="words-slider"
                type="range"
                min="6"
                max="12"
                value={wordCount}
                onChange={(e) => setWordCount(parseInt(e.target.value, 10))}
                className="w-full accent-primary"
              />

              <div className="grid grid-cols-2 gap-3 pt-2 text-xs">
                <div>
                  <Label htmlFor="separator-input" className="text-xs">
                    Separator
                  </Label>
                  <Input
                    id="separator-input"
                    value={separator}
                    maxLength={3}
                    onChange={(e) => setSeparator(e.target.value)}
                    className="h-8 mt-1"
                  />
                </div>
                <div className="space-y-2 pt-2">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={capitalize}
                      onChange={(e) => setCapitalize(e.target.checked)}
                      className="rounded accent-primary"
                    />
                    Capitalize words
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeNumber}
                      onChange={(e) => setIncludeNumber(e.target.checked)}
                      className="rounded accent-primary"
                    />
                    Append number
                  </label>
                </div>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          {onSelectPassword && (
            <Button type="button" onClick={handleApply}>
              Use Password
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

