// S2's gate (REARCH R12): the registry's lifecycle on the Durable
// Object — create, list, point-in-time reads, supersession, and the
// journal replaying into a fresh instance — on a plain in-memory
// storage with the same API DO storage carries.

import { describe, expect, it } from "vitest";
import {
  ITEM_CLASSES,
  RegistryDO,
  type JournalOp,
  type Item,
} from "../src/registry-do";

class FakeStorage {
  private map = new Map<string, unknown>();
  async put(key: string, value: unknown): Promise<void> {
    this.map.set(key, value);
  }
  async get(key: string): Promise<unknown> {
    return this.map.get(key);
  }
  async list(options: { prefix: string }): Promise<Map<string, unknown>> {
    return new Map(
      [...this.map.entries()].filter(([key]) => key.startsWith(options.prefix)),
    );
  }
  entries(): [string, unknown][] {
    return [...this.map.entries()];
  }
}

const make = (storage: FakeStorage) => new RegistryDO(storage);
const serve = (registry: RegistryDO, path: string, init?: RequestInit): Promise<Response> =>
  registry.fetch(new Request(`https://do.internal${path}`, init));

const createBody = {
  register_id: "unidpp-issuer",
  item_id: "urn:unidpp:profile:s2-do",
  class: "profile",
  definition: "The S2 Durable Object profile",
  version: "1.0.0",
  submitting_organization: "unidpp-worker",
};

describe("the registry Durable Object", () => {
  it("registers an item and serves its view", async () => {
    const registry = make(new FakeStorage());
    const created = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify(createBody),
    });
    expect(created.status).toBe(201);
    const body = (await created.json()) as Record<string, unknown>;
    expect(body.identifier).toBe(createBody.item_id);
    expect(body.item_class).toBe("profile");
    expect((body.versions as unknown[]).length).toBe(1);
    expect(body.audit_seq).toBe(1);
    expect(created.headers.get("x-as-of")).toBeTruthy();

    const read = await serve(registry, `/items/${encodeURIComponent(createBody.item_id)}`);
    expect(read.status).toBe(200);
    const view = (await read.json()) as Record<string, unknown>;
    expect(view.identifier).toBe(createBody.item_id);
    const version = view.version as Record<string, unknown>;
    expect(version.status).toBe("valid");
  });

  it("refuses duplicates, bad classes, and invalid statuses", async () => {
    const registry = make(new FakeStorage());
    await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify(createBody),
    });
    const duplicate = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify(createBody),
    });
    expect(duplicate.status).toBe(400);
    const badClass = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({ ...createBody, item_id: "urn:x:y", class: "widget" }),
    });
    expect(badClass.status).toBe(400);
    const badStatus = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({ ...createBody, item_id: "urn:x:z", status: "superseded" }),
    });
    expect(badStatus.status).toBe(400);
    const badToken = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({ ...createBody, item_id: "has space" }),
    });
    expect(badToken.status).toBe(400);
    const model = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({ ...createBody, item_id: "urn:x:m", class: "model" }),
    });
    expect(model.status).toBe(400);
    const unpinned = await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({
        ...createBody,
        item_id: "urn:x:p",
        manifest: { version: "9.9.9" },
      }),
    });
    expect(unpinned.status).toBe(400);
  });

  it("lists with class and register filters", async () => {
    const registry = make(new FakeStorage());
    await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify(createBody),
    });
    await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify({
        register_id: "unidpp-issuer",
        item_id: "unit-kwh",
        class: "unit",
        definition: "The kilowatt-hour",
        version: "1",
      }),
    });
    const all = (await (await serve(registry, "/items")).json()) as {
      count: number;
      items: unknown[];
    };
    expect(all.count).toBe(2);
    const profiles = (await (await serve(registry, "/items?class=profile")).json()) as {
      count: number;
    };
    expect(profiles.count).toBe(1);
    const none = (await (await serve(registry, "/items?register=nowhere")).json()) as {
      count: number;
    };
    expect(none.count).toBe(0);
    expect(ITEM_CLASSES).toContain("cross-register-mapping");
  });

  it("supersedes: the window closes, the chain links", async () => {
    const registry = make(new FakeStorage());
    await serve(registry, "/items", {
      method: "POST",
      body: JSON.stringify(createBody),
    });
    const superseded = await serve(
      registry,
      `/items/${encodeURIComponent(createBody.item_id)}/versions`,
      {
        method: "POST",
        body: JSON.stringify({ version: "1.1.0", reason: "the S2 supersession" }),
      },
    );
    expect(superseded.status).toBe(201);
    const body = (await superseded.json()) as Record<string, unknown>;
    expect(body.audit_seq).toBe(2);
    expect(body.reason).toBe("the S2 supersession");
    const item = body.item as { versions: Record<string, unknown>[] };
    expect(item.versions.length).toBe(2);
    const oldVersion = item.versions.find((v) => v.version === "1.0.0")!;
    expect(oldVersion.status).toBe("superseded");
    expect(oldVersion.superseded_by_version).toBe("1.1.0");
    expect(oldVersion.window_end).toBeTruthy();
    const missingReason = await serve(
      registry,
      `/items/${encodeURIComponent(createBody.item_id)}/versions`,
      { method: "POST", body: JSON.stringify({ version: "2.0.0" }) },
    );
    expect(missingReason.status).toBe(400);
  });

  it("replays the journal into a fresh instance", async () => {
    const storage = new FakeStorage();
    const first = make(storage);
    await serve(first, "/items", { method: "POST", body: JSON.stringify(createBody) });
    await serve(first, `/items/${encodeURIComponent(createBody.item_id)}/versions`, {
      method: "POST",
      body: JSON.stringify({ version: "1.1.0", reason: "replayed" }),
    });
    // A second instance on the same storage: the journal replays.
    const second = make(storage);
    const read = await serve(second, `/items/${encodeURIComponent(createBody.item_id)}`);
    expect(read.status).toBe(200);
    const view = (await read.json()) as { versions: { version: string; status: string }[] };
    expect(view.versions.length).toBe(2);
    expect(view.versions[0].status).toBe("superseded");
    expect(view.versions[1].status).toBe("valid");
    const journal = storage
      .entries()
      .filter(([key]) => key.startsWith("journal:"))
      .map(([key, value]) => ({ key, value }) as { key: string; value: JournalOp & Item });
    expect(journal.length).toBe(2);
    expect(journal[0].value.op).toBe("register-item");
    expect(journal[1].value.op).toBe("supersede-version");
  });

  it("states its misses", async () => {
    const registry = make(new FakeStorage());
    const absent = await serve(registry, "/items/definitely-absent");
    expect(absent.status).toBe(404);
    const supersedeAbsent = await serve(registry, "/items/definitely-absent/versions", {
      method: "POST",
      body: JSON.stringify({ version: "2", reason: "nope" }),
    });
    expect(supersedeAbsent.status).toBe(404);
  });
});
