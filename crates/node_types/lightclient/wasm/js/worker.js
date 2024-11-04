import init, { LightClientWorker } from "../pkg/prism_wasm_lightclient.js";

self.onmessage = async function(e) {
    if (e.data.type === 'INIT') {
        // Get the port from the message event
        const port = e.ports[0];
        
        // Create and initialize the worker
        workerInstance = await new LightClientWorker();
        
        // Start running the worker with the received port
        workerInstance.run().catch(error => {
            console.error("Worker error:", error);
        });

        // Clean up the initial message handler since we only need it once
        self.onmessage = null;
    }
};

let worker = new LightClientWorker(self);

console.log("Starting LightClientWorker");

worker.run().catch(error => {
    console.error("Worker error:", error);
});