// The rule-expression language v0 (R10 G4), the estate's port of the
// registry's own grammar — the same tokens, the same precedence, the
// same fixed semantics: an absent fact reads false, a kind mismatch
// reads false, the ordering operators are decimal-only, and `in`
// reads membership over string and decimal facts. The descriptor
// intake validates the expressions (parse, declared paths, literal
// kinds compatible with the declared features); the instance intake
// evaluates every referenced rule and names the failing rule and its
// expression.

export interface ParseError {
  offset: number;
  message: string;
}

export type Op = "=" | "!=" | ">" | ">=" | "<" | "<=";

export type Lit =
  | { kind: "decimal"; value: number }
  | { kind: "string"; value: string }
  | { kind: "boolean"; value: boolean };

export type Expr =
  | { t: "comparison"; path: string; op: Op; literal: Lit }
  | { t: "in"; path: string; members: Lit[] }
  | { t: "and"; left: Expr; right: Expr }
  | { t: "or"; left: Expr; right: Expr }
  | { t: "not"; inner: Expr };

class Parser {
  private pos = 0;
  constructor(private readonly source: string) {}

  private offset(): number {
    // The offset counts UTF-16 units; the refusal names it as a
    // position in the author's text.
    return Math.min(this.pos, this.source.length);
  }

  private err(message: string): ParseError {
    return { offset: this.offset(), message };
  }

  private skipSpaces(): void {
    while (this.pos < this.source.length && /\s/.test(this.source[this.pos])) {
      this.pos += 1;
    }
  }

  private peekWord(): string {
    const match = /^[A-Za-z0-9_-]+/.exec(this.source.slice(this.pos));
    return match ? match[0] : "";
  }

  private takeWord(): string | null {
    this.skipSpaces();
    const word = this.peekWord();
    if (!word) return null;
    this.pos += word.length;
    return word;
  }

  private takeExact(token: string): boolean {
    this.skipSpaces();
    if (this.source.startsWith(token, this.pos)) {
      this.pos += token.length;
      return true;
    }
    return false;
  }

  parse(): Expr {
    const expr = this.parseOr();
    this.skipSpaces();
    if (this.pos !== this.source.length) {
      throw this.err("unexpected trailing input");
    }
    return expr;
  }

  private parseOr(): Expr {
    let left = this.parseAnd();
    for (;;) {
      this.skipSpaces();
      const save = this.pos;
      if (this.takeWord() === "or") {
        left = { t: "or", left, right: this.parseAnd() };
      } else {
        this.pos = save;
        return left;
      }
    }
  }

  private parseAnd(): Expr {
    let left = this.parseUnary();
    for (;;) {
      this.skipSpaces();
      const save = this.pos;
      if (this.takeWord() === "and") {
        left = { t: "and", left, right: this.parseUnary() };
      } else {
        this.pos = save;
        return left;
      }
    }
  }

  private parseUnary(): Expr {
    this.skipSpaces();
    const save = this.pos;
    if (this.takeWord() === "not") {
      return { t: "not", inner: this.parseUnary() };
    }
    this.pos = save;
    return this.parsePrimary();
  }

  private parsePrimary(): Expr {
    this.skipSpaces();
    if (this.pos >= this.source.length) {
      throw this.err("the expression ends where a term was expected");
    }
    if (this.source[this.pos] === "(") {
      this.pos += 1;
      const inner = this.parseOr();
      this.skipSpaces();
      if (!this.takeExact(")")) throw this.err("expected `)`");
      return inner;
    }
    return this.parseComparison();
  }

  private parsePath(): string {
    this.skipSpaces();
    let path = "";
    for (;;) {
      const word = this.peekWord();
      if (!word) {
        if (!path) throw this.err("expected a fact path");
        throw this.err("a fact path ends in a dot");
      }
      path += word;
      this.pos += word.length;
      if (this.source[this.pos] === ".") {
        path += ".";
        this.pos += 1;
      } else {
        return path;
      }
    }
  }

  private parseComparison(): Expr {
    const path = this.parsePath();
    this.skipSpaces();
    const save = this.pos;
    if (this.takeWord() === "in") {
      this.skipSpaces();
      if (!this.takeExact("[")) throw this.err("expected `[` after `in`");
      const members: Lit[] = [];
      for (;;) {
        members.push(this.parseLiteral());
        this.skipSpaces();
        if (this.takeExact(",")) continue;
        if (this.takeExact("]")) break;
        throw this.err("expected `,` or `]` in the membership list");
      }
      return { t: "in", path, members };
    }
    this.pos = save;
    let op: Op;
    if (this.takeExact("!=")) op = "!=";
    else if (this.takeExact(">=")) op = ">=";
    else if (this.takeExact("<=")) op = "<=";
    else if (this.takeExact("=")) op = "=";
    else if (this.takeExact(">")) op = ">";
    else if (this.takeExact("<")) op = "<";
    else throw this.err("expected a comparison operator");
    return { t: "comparison", path, op, literal: this.parseLiteral() };
  }

  private parseLiteral(): Lit {
    this.skipSpaces();
    if (this.pos >= this.source.length) {
      throw this.err("the expression ends where a literal was expected");
    }
    const quote = this.source[this.pos];
    if (quote === '"' || quote === "'") {
      this.pos += 1;
      let text = "";
      while (this.pos < this.source.length && this.source[this.pos] !== quote) {
        text += this.source[this.pos];
        this.pos += 1;
      }
      if (this.pos >= this.source.length) {
        throw this.err("the string literal runs past the end");
      }
      this.pos += 1;
      return { kind: "string", value: text };
    }
    const word = this.peekWord();
    if (word === "true") {
      this.pos += word.length;
      return { kind: "boolean", value: true };
    }
    if (word === "false") {
      this.pos += word.length;
      return { kind: "boolean", value: false };
    }
    const match = /^\d+(\.\d+)?/.exec(this.source.slice(this.pos));
    if (match) {
      this.pos += match[0].length;
      return { kind: "decimal", value: Number(match[0]) };
    }
    throw this.err("expected a literal (number, `true`, `false` or a quoted string)");
  }
}

export function parseRule(source: string): { ok: true; expr: Expr } | { ok: false; error: ParseError } {
  try {
    return { ok: true, expr: new Parser(source).parse() };
  } catch (e) {
    return { ok: false, error: e as ParseError };
  }
}

// The evaluator (total: absent facts and kind mismatches read false).
export function evalRule(expr: Expr, facts: Record<string, unknown>): boolean {
  switch (expr.t) {
    case "comparison": {
      const fact = facts[expr.path];
      if (fact === undefined || fact === null) return false;
      const literal = expr.literal;
      if (literal.kind === "string") {
        return expr.op === "="
          ? fact === literal.value
          : expr.op === "!="
            ? fact !== literal.value
            : false;
      }
      if (literal.kind === "boolean") {
        return expr.op === "="
          ? fact === literal.value
          : expr.op === "!="
            ? fact !== literal.value
            : false;
      }
      if (typeof fact !== "number") return false;
      switch (expr.op) {
        case "=":
          return fact === literal.value;
        case "!=":
          return fact !== literal.value;
        case ">":
          return fact > literal.value;
        case ">=":
          return fact >= literal.value;
        case "<":
          return fact < literal.value;
        case "<=":
          return fact <= literal.value;
      }
      return false;
    }
    case "in": {
      const fact = facts[expr.path];
      if (fact === undefined || fact === null) return false;
      return expr.members.some((member) => {
        if (member.kind === "string") return fact === member.value;
        if (member.kind === "decimal") return fact === member.value;
        return fact === member.value;
      });
    }
    case "and":
      return evalRule(expr.left, facts) && evalRule(expr.right, facts);
    case "or":
      return evalRule(expr.left, facts) || evalRule(expr.right, facts);
    case "not":
      return !evalRule(expr.inner, facts);
  }
}

// A walk over every comparison the expression carries.
function walk(expr: Expr, visit: (e: Expr) => void): void {
  visit(expr);
  if (expr.t === "and" || expr.t === "or") {
    walk(expr.left, visit);
    walk(expr.right, visit);
  } else if (expr.t === "not") {
    walk(expr.inner, visit);
  }
}

// The descriptor-side errors against the declared features: the same
// rules the native chain enforces, with the path named.
export function ruleDescriptorErrors(
  expr: Expr,
  features: Map<string, string>,
): string[] {
  const errors: string[] = [];
  walk(expr, (e) => {
    if (e.t !== "comparison" && e.t !== "in") return;
    const kind = features.get(e.path);
    if (!kind) {
      errors.push(`the expression names \`${e.path}\`, which the descriptor does not declare`);
      return;
    }
    if (e.t === "in") {
      if (kind !== "string" && kind !== "decimal") {
        errors.push(
          `the membership test on \`${e.path}\` reads a ${kind} feature; \`in\` reads string and decimal facts`,
        );
      }
      return;
    }
    const literal = e.literal;
    if (kind === "decimal" && literal.kind !== "decimal") {
      errors.push(`the comparison on \`${e.path}\` pits a decimal feature against a ${literal.kind} literal`);
    } else if (kind === "string" && literal.kind !== "string") {
      errors.push(`the comparison on \`${e.path}\` pits a string feature against a ${literal.kind} literal`);
    } else if (kind === "boolean" && literal.kind !== "boolean") {
      errors.push(`the comparison on \`${e.path}\` pits a boolean feature against a ${literal.kind} literal`);
    }
    if (
      (e.op === ">" || e.op === ">=" || e.op === "<" || e.op === "<=") &&
      kind !== "decimal"
    ) {
      errors.push(
        `the ordering comparison on \`${e.path}\` reads a ${kind} feature; the ordering operators are decimal-only`,
      );
    }
  });
  return errors;
}
