import { useState } from 'react'
import init, { LightClientWorker, WasmLightClient } from "../../pkg/prism_wasm_lightclient.js";
/* import OperationSubmitter from './components/OperationSubmitter.js'; */

function App() {
  const [status, setStatus] = useState('Not started')
  const [height, setHeight] = useState(0)
  const [client, setClient] = useState<WasmLightClient | null>(null)

  const startLightClient = async () => {
    try {
      setStatus('Initializing...')
      await init()

      const channel = new MessageChannel()
      const worker = await new LightClientWorker(channel.port1)
      worker.run()
      
      const client = await new WasmLightClient(channel.port2)
      setClient(client);
      setStatus('Running')

      channel.port2.onmessage = (event) => {
        console.log('Message from worker:', event.data)
      }

      // TODO: implement the message logic
      setInterval(async () => {
        const height = await client.getCurrentHeight()
        setHeight(parseInt(height.toString()))
      }, 1000)

    } catch (error) {
      console.error(error)
      setStatus(`Error: ${error}`)
    }
  }

/*   const verifyRandomEpoch = async () => {
    try {
      setStatus('Verifying epoch...')
      setStatus('Epoch verified successfully')
    } catch (error) {
      setStatus(`Verification failed: ${error}`)
    }
  } */

  return (
    <div className="max-w-2xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">Light Client Test</h1>
      
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-lg font-semibold mb-2">Status</h2>
        <div className="flex items-center gap-2 mb-2">
          <div className={`w-2 h-2 rounded-full ${
            status === 'Running' ? 'bg-green-500' : 'bg-red-500'
          }`} />
          <span>{status}</span>
        </div>
        <div>Current Height: {height}</div>
      </div>

      <div className="space-x-4">
        <button
          onClick={startLightClient}
          className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:bg-gray-400"
        >
          Start Light Client
        </button>
        
        {/* <button
          onClick={verifyRandomEpoch}
          disabled={!client}
          className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 disabled:bg-gray-400"
        >
          Verify Random Epoch
        </button> */}
      </div>
      {/* client && <OperationSubmitter /> */}
    </div>
  )
}

export default App