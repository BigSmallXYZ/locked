// Long-poll wake-ups: `wait` resolves the moment a form is submitted or an approval decided.

const waiters = new Map<string, Set<() => void>>();

export function notify(id: string) {
  const set = waiters.get(id);
  if (!set) return;
  waiters.delete(id);
  for (const wake of set) wake();
}

/** Resolves on notify(id) or after timeoutMs, whichever is first. */
export function waitFor(id: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve) => {
    let set = waiters.get(id);
    if (!set) waiters.set(id, (set = new Set()));
    const wake = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      waiters.get(id)?.delete(wake);
      resolve();
    }, timeoutMs);
    set.add(wake);
  });
}
