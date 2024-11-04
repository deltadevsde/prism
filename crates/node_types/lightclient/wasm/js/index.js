import { WasmLightClient } from "../pkg/prism_wasm_lightclient.js";

export async function runLightClient() {

	const channel = new MessageChannel();

  	const worker = new Worker(new URL("worker.js", import.meta.url), { type: "module" });

	worker.postMessage({ type: "init", port: channel.port1 }, [channel.port1]);

  	const client = await new WasmLightClient(channel.port2);

	console.log(worker);
	console.log(client);
  
  	return client;
} 