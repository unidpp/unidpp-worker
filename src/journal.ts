// The journal abstraction shared by every Durable Object (REARCH
// R12): append-only ops, replayed in order. workerd's SQLite-backed
// DO storage carries the sql API; the tests ride a plain map with the
// same contract.

export interface JournalOp {
  op: string;
  [key: string]: unknown;
}

export interface Journal {
  append(op: JournalOp): Promise<number>;
  all(): Promise<JournalOp[]>;
}

export class SqlJournal implements Journal {
  readonly kind = "sql";
  private sql: {
    exec(query: string, ...params: unknown[]): { toArray(): unknown[] };
  };
  constructor(storage: { sql: unknown }) {
    this.sql = storage.sql as typeof this.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS journal (seq INTEGER PRIMARY KEY, line TEXT)",
    );
  }
  async append(op: JournalOp): Promise<number> {
    const next = this.sql
      .exec("SELECT COALESCE(MAX(seq), 0) + 1 AS seq FROM journal")
      .toArray()[0] as { seq: number };
    this.sql.exec(
      "INSERT INTO journal (seq, line) VALUES (?, ?)",
      next.seq,
      JSON.stringify(op),
    );
    return next.seq as number;
  }
  async all(): Promise<JournalOp[]> {
    const rows = this.sql.exec("SELECT line FROM journal ORDER BY seq").toArray();
    const ops: JournalOp[] = [];
    for (const row of rows) {
      const text = typeof row === "string" ? row : String((row as { line?: unknown }).line ?? "");
      let value: unknown = text;
      for (let i = 0; i < 3 && typeof value === "string"; i += 1) {
        value = JSON.parse(value);
      }
      ops.push(value as JournalOp);
    }
    return ops;
  }
}

export interface MapStorage {
  put(key: string, value: unknown): Promise<void>;
  get(key: string): Promise<unknown>;
  list(options: { prefix: string }): Promise<Map<string, unknown>>;
}

export class MapJournal implements Journal {
  private ops: JournalOp[] = [];
  constructor(private readonly storage: MapStorage) {}
  async append(op: JournalOp): Promise<number> {
    this.ops.push(op);
    await this.storage.put(
      `journal:${String(this.ops.length).padStart(6, "0")}`,
      op,
    );
    return this.ops.length;
  }
  async all(): Promise<JournalOp[]> {
    const stored = await this.storage.list({ prefix: "journal:" });
    if (stored.size > 0) {
      this.ops = [...stored.entries()]
        .sort()
        .map(([, value]) => value as JournalOp);
    }
    return this.ops;
  }
}

export function journalFor(stateOrStorage: unknown): Journal {
  const source =
    (stateOrStorage as { storage?: unknown }).storage ?? stateOrStorage;
  const sql = (source as { sql?: unknown }).sql;
  return sql
    ? new SqlJournal(source as { sql: unknown })
    : new MapJournal(source as MapStorage);
}
