import { EFF_SHORT_WORDLIST } from "./wordlist"

export interface CharacterGeneratorOptions {
  length?: number // 8 to 64
  uppercase?: boolean
  lowercase?: boolean
  numbers?: boolean
  symbols?: boolean
  avoidAmbiguous?: boolean
}

export interface PassphraseGeneratorOptions {
  wordCount?: number // minimum 6
  separator?: string
  capitalize?: boolean
  includeNumber?: boolean
}

const LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const NUMBERS = "0123456789"
const SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
const AMBIGUOUS = new Set(["0", "O", "o", "1", "l", "I", "|", "`", "'", "\""])

/**
 * Uniformly selects a random integer in [0, max - 1] without modulo bias
 * using rejection sampling.
 */
function secureRandomInt(max: number): number {
  if (max <= 0) throw new RangeError("max must be positive")
  if (max <= 256) {
    const limit = 256 - (256 % max)
    const buf = new Uint8Array(1)
    while (true) {
      crypto.getRandomValues(buf)
      const val = buf[0]!
      if (val < limit) {
        return val % max
      }
    }
  }

  // For max up to 65536 (e.g. 1296 wordlist)
  const limit = 65536 - (65536 % max)
  const buf = new Uint16Array(1)
  while (true) {
    crypto.getRandomValues(buf)
    const val = buf[0]!
    if (val < limit) {
      return val % max
    }
  }
}

/**
 * Generates a random character-based password.
 */
export function generatePassword(options: CharacterGeneratorOptions = {}): string {
  const length = Math.max(8, Math.min(64, options.length ?? 20))
  const useUpper = options.uppercase ?? true
  const useLower = options.lowercase ?? true
  const useNumbers = options.numbers ?? true
  const useSymbols = options.symbols ?? true
  const avoidAmbiguous = options.avoidAmbiguous ?? true

  const filterAmbiguous = (charset: string) =>
    avoidAmbiguous ? charset.split("").filter((c) => !AMBIGUOUS.has(c)).join("") : charset

  const sets: string[] = []
  if (useLower) sets.push(filterAmbiguous(LOWERCASE))
  if (useUpper) sets.push(filterAmbiguous(UPPERCASE))
  if (useNumbers) sets.push(filterAmbiguous(NUMBERS))
  if (useSymbols) sets.push(filterAmbiguous(SYMBOLS))

  if (sets.length === 0) {
    // Fallback if user unchecks everything
    sets.push(filterAmbiguous(LOWERCASE))
  }

  const combinedCharset = sets.join("")
  const resultChars: string[] = []

  // Ensure at least one character from each active character set
  for (const set of sets) {
    if (set.length > 0) {
      resultChars.push(set[secureRandomInt(set.length)]!)
    }
  }

  // Fill remaining length from combined set
  while (resultChars.length < length) {
    resultChars.push(combinedCharset[secureRandomInt(combinedCharset.length)]!)
  }

  // Fisher-Yates shuffle using secureRandomInt
  for (let i = resultChars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1)
    const temp = resultChars[i]!
    resultChars[i] = resultChars[j]!
    resultChars[j] = temp
  }

  return resultChars.join("")
}

/**
 * Generates a Diceware passphrase using the bundled EFF Short Wordlist.
 * Guarantees at least 6 words (~60 bits of entropy).
 */
export function generatePassphrase(options: PassphraseGeneratorOptions = {}): string {
  const wordCount = Math.max(6, options.wordCount ?? 6)
  const separator = options.separator ?? "-"
  const capitalize = options.capitalize ?? false
  const includeNumber = options.includeNumber ?? false

  const listLength = EFF_SHORT_WORDLIST.length
  const words: string[] = []

  for (let i = 0; i < wordCount; i++) {
    const index = secureRandomInt(listLength)
    let word = EFF_SHORT_WORDLIST[index]!
    if (capitalize) {
      word = word.charAt(0).toUpperCase() + word.slice(1)
    }
    words.push(word)
  }

  if (includeNumber) {
    const num = secureRandomInt(10)
    const insertPos = secureRandomInt(words.length)
    words[insertPos] = `${words[insertPos]}${num}`
  }

  return words.join(separator)
}

