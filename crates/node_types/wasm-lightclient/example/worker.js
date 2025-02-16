import init, { LightClientWorker } from '../pkg/prism_wasm_lightclient.js';

Error.stackTraceLimit = 99;

await init();
console.log("Starting LightClientWorker");

let worker = await new LightClientWorker(self, "specter", "events-channel");

console.log(worker);

self.onmessage = (event) => {
    console.log("Worker received message:", event.data);
};

await worker.run();
