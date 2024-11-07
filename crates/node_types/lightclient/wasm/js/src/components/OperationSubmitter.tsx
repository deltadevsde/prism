import { useState } from 'react';
import type { Operation } from '../types/operationTypes';
import * as ed from '@noble/ed25519'
import { sha512 } from '@noble/hashes/sha512'

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const servicePrivateKey = new Uint8Array([
	80,157,217,232,106,14,240,149,137,114,229,48,104,56,152,140,61,145,101,7,182,125,113,113,164,184,49,176,19,71,62,53
  ]);

const OperationSubmitter = () => {
  const [operations, setOperations] = useState<Operation[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [selectedType, setSelectedType] = useState<string>('CreateAccount');

  const generateRandomOperation = (): Operation => {
    const randomId = `user${Date.now()}${Math.floor(Math.random() * 1000)}@example.com`;
    const serviceId = 'test_service';
    
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = ed.getPublicKey(privateKey);

    switch (selectedType) {
      case 'CreateAccount': {
        const operationToSign = {
          CreateAccount: {
            id: randomId,
            value: {
              Ed25519: Array.from(publicKey)
            },
            service_id: serviceId,
            signature: [],
            challenge: {
              Signed: []
            }
          }
        };

        const messageBytes = new TextEncoder().encode(JSON.stringify(operationToSign));
        const signature = ed.sign(messageBytes, privateKey);

		const forServiceToSign = {
			CreateAccount: {
				...operationToSign.CreateAccount,
				signature: Array.from(signature),
				challenge: {
					Signed: []
				}
			  }
		};

		const messageBytesForService = new TextEncoder().encode(JSON.stringify(forServiceToSign));
		const signatureForService = ed.sign(messageBytesForService, servicePrivateKey);

        return {
			CreateAccount: {
				...forServiceToSign.CreateAccount,
				challenge: {
					Signed: Array.from(signatureForService)
				}
			}
		};
      }

      case 'AddKey': {
        const operationToSign = {
          AddKey: {
            id: randomId,
            value: {
              Ed25519: Array.from(publicKey)
            },
            signature: {
              key_idx: 0,
              signature: []
            }
          }
        };

        const messageBytes = new TextEncoder().encode(JSON.stringify(operationToSign));
        const signature = ed.sign(messageBytes, privateKey);

        return {
          AddKey: {
            ...operationToSign.AddKey,
            signature: {
              key_idx: 0,
              signature: Array.from(signature)
            }
          }
        };
      }

      case 'RevokeKey': {
        const operationToSign = {
          RevokeKey: {
            id: randomId,
            value: {
              Ed25519: Array.from(publicKey)
            },
            signature: {
              key_idx: 0,
              signature: []
            }
          }
        };

        const messageBytes = new TextEncoder().encode(JSON.stringify(operationToSign));
        const signature = ed.sign(messageBytes, privateKey);

        return {
          RevokeKey: {
            ...operationToSign.RevokeKey,
            signature: {
              key_idx: 0,
              signature: Array.from(signature)
            }
          }
        };
      }

      case 'AddData': {
        const operationToSign = {
          AddData: {
            id: randomId,
            value: Array.from(new TextEncoder().encode('test data')),
            value_signature: null,
            op_signature: {
              key_idx: 0,
              signature: []
            }
          }
        };

        const messageBytes = new TextEncoder().encode(JSON.stringify(operationToSign));
        const signature = ed.sign(messageBytes, privateKey);

        return {
          AddData: {
            ...operationToSign.AddData,
            op_signature: {
              key_idx: 0,
              signature: Array.from(signature)
            }
          }
        };
      }

      case 'RegisterService': {
        const operationToSign = {
          RegisterService: {
            id: serviceId,
            creation_gate: {
              Signed: {
                Ed25519: Array.from(ed.getPublicKey(servicePrivateKey))
              }
            }
          }
        };

        // RegisterService doesn't need a signature, just return as is
        return operationToSign;
      }

      default:
        throw new Error(`Unknown operation type: ${selectedType}`);
    }
  };

  const submitRandomOperation = async () => {
    try {
      setSubmitting(true);
      const operation = generateRandomOperation();
      
      setOperations(prev => [operation, ...prev].slice(0, 5)); // Keep last 5 operations for good looking UI🤓
      
	  const requestBody = { 
        operation: operation
      };

	  console.log('Sending request operation...');
      
	  const response = await fetch('http://localhost:3001/update-entry', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });

      const responseText = await response.text();
      console.log('Response status:', response.status);
      console.log('Response body:', responseText);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
    } catch (error) {
      console.error('Failed to submit operation:', error);
    } finally {
      setSubmitting(false);
    }
  };

  const getOperationDescription = (op: Operation): string => {
    if ('CreateAccount' in op) return `Create Account: ${op.CreateAccount.id}`;
    if ('AddKey' in op) return `Add Key: ${op.AddKey.id}`;
    if ('RevokeKey' in op) return `Revoke Key: ${op.RevokeKey.id}`;
    if ('AddData' in op) return `Add Data: ${op.AddData.id}`;
    if ('RegisterService' in op) return `Register Service: ${op.RegisterService.id}`;
    return 'Unknown Operation';
  };

  return (
    <div className="bg-white rounded-lg shadow p-6 mt-6">
      <h2 className="text-lg font-semibold mb-4">Operation Submitter</h2>
      
      <div className="mb-4">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Operation Type
        </label>
        <select
          value={selectedType}
          onChange={(e) => setSelectedType(e.target.value)}
          className="w-full px-3 py-2 border rounded-md"
        >
          <option value="CreateAccount">Create Account</option>
          <option value="AddKey">Add Key</option>
          <option value="RevokeKey">Revoke Key</option>
          <option value="AddData">Add Data</option>
          <option value="RegisterService">Register Service</option>
        </select>
      </div>
      
      <button
        onClick={submitRandomOperation}
        disabled={submitting}
        className="bg-purple-500 text-white px-4 py-2 rounded hover:bg-purple-600 disabled:bg-gray-400 mb-4"
      >
        {submitting ? 'Submitting...' : 'Submit Operation'}
      </button>
      
      <div className="mt-4">
        <h3 className="text-md font-semibold mb-2">Recent Operations</h3>
        {operations.length === 0 ? (
          <p className="text-gray-500">No operations submitted yet</p>
        ) : (
          <div className="space-y-2">
            {operations.map((op, index) => (
              <div key={index} className="border rounded p-2 text-sm">
                <div className="font-medium">{getOperationDescription(op)}</div>
                <div className="text-gray-400 text-xs">
                  {new Date().toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default OperationSubmitter;