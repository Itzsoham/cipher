import { ZxcvbnFactory } from "@zxcvbn-ts/core"
import * as common from "@zxcvbn-ts/language-common"

const zxcvbn = new ZxcvbnFactory({
  dictionary: common.dictionary,
  graphs: common.adjacencyGraphs,
})

export interface PasswordStrengthResult {
  score: number // 0 to 4
  warning?: string
  suggestions: string[]
}

/**
 * Evaluates password strength using zxcvbn-ts on a 0-4 scale.
 * User inputs (e.g. email, name, username) should be passed to penalize
 * passwords containing personal information.
 */
export function evaluatePasswordStrength(
  password: string,
  userInputs?: (string | number)[]
): PasswordStrengthResult {
  if (!password) {
    return { score: 0, suggestions: [] }
  }

  const sanitizedInputs = (userInputs ?? [])
    .map((input) => String(input).trim().toLowerCase())
    .filter((input) => input.length > 2)

  const result = zxcvbn.check(password, sanitizedInputs)

  return {
    score: result.score,
    warning: result.feedback.warning || undefined,
    suggestions: result.feedback.suggestions ?? [],
  }
}
