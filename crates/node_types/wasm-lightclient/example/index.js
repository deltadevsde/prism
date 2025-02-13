export async function spawnWorker() {
  let worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  return worker;
}
