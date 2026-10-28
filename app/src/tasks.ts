// Long tasks that keep going when the user switches pages: Health Check, folder scans, sandbox runs, home checks.
// Pages report them here; App shows them in the title bar and tells the user when they leave one running or one finishes.

import { useEffect, useSyncExternalStore } from "react";

export type Task = { id: string; label: string; page: string };

let tasks: Task[] = [];
const listeners = new Set<() => void>();

function update(next: Task[]) {
  tasks = next;
  listeners.forEach((l) => l());
}

/** Registers a task while `active` is true. `label` is already translated: it is shown as is. */
export function useTask(id: string, label: string, page: string, active: boolean) {
  useEffect(() => {
    if (!active) return;
    update([...tasks.filter((t) => t.id !== id), { id, label, page }]);
    return () => update(tasks.filter((t) => t.id !== id));
  }, [id, label, page, active]);
}

export function useRunningTasks(): Task[] {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => tasks,
  );
}

export function runningTasks(): Task[] {
  return tasks;
}
