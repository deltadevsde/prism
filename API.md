It makes sense and is necessary to build different frontends in order to use the transparency dictionaries. In the following section, we will provide a brief overview of the most important interfaces for interacting with Deimos.

### Update the Dictionary

The update operation causes either the hashchain for an existing entry to be updated (i.e. an entry is added to the hashchain) or, if the ID does not yet exist, it's added as a new ID to the Transparency Dictionary and the associated value is the first and last value of the associated hashchain to date.

```bash
curl -X POST http://localhost:8080/update-entry \
      -H "Content-Type: application/json" \
      -d '{ "id": "YOUR_ID", \
            "public_key": "YOUR_PUBLIC_KEY", \
            "signed_message": "YOUR_SIGNED_MESSAGE"}'
```

### Get all derived and normal dictionary

```bash
curl http://localhost:8080/get-dictionaries
```

Returns both the tranparency dictionary with all entries and the derived dictionary containing only the hashed ids together with the hash value of the last block of the corresponding hashchain in the following format:

```javascript
{
  "dict":[
    { "id": "FIRST_ID",
      "value": [
        {"hash":"FIRST_BLOCK_HASH","previous_hash":"000..","operation":"...","value":"FIRST_HASHED_VALUE"}
        {"hash":"SECOND_BLOCK_HASH","previous_hash":"FIRST_BLOCK_HASH","operation":"...","value":"SECOND_HASHED_VALUE"}
      ]
    },
    { "id": "SECOND_ID",
      "value": [
        {"hash":"FIRST_BLOCK_HASH","previous_hash":"000...","operation":"...","value":"FIRST_HASHED_VALUE"}
        {"hash":"SECOND_BLOCK_HASH","previous_hash":"FIRST_BLOCK_HASH","operation":"...","value":"SECOND_HASHED_VALUE"}
      ]
    },
  ],
  "derived_dict": [
    { "id": "HASHED_FIRST_ID", "value": "HASH_OF_LAST_BLOCK"},
    { "id": "HASHED_SECOND_ID", "value": "HASH_OF_LAST_BLOCK"}
  ]
}
```

### Get derived and normal dictionary for given ID

```bash
curl http://localhost:8080/get-dictionary/{ID}
```

Returns the tranparency dictionary with all entries for the given ID in the following format:

```javascript
{
  "id": "ID",
  "dict": [
    { "hash": "FIRST_BLOCK_HASH", "previous_hash": "000...", "operation": "...", "value": "FIRST_HASHED_VALUE" },
    { "hash": "SECOND_BLOCK_HASH", "previous_hash": "000...", "operation": "...", "value": "SECOND_HASHED_VALUE" },
  ]
}
```

### Validate epoch for given epoch number

```bash
curl -X POST http://localhost:8080/validate-epoch -H "Content-Type: application/json" -d '"EPOCH_NUMBER"'
```

This API request validates a Groth16 zk-SNARK created with the Merkle proofs of the past epoch. The EPOCH_NUMBER in the request should be replaced with the actual value of the epoch. The API response contains points on the BLS12-381 elliptical curve, represented by the keys 'a', 'b' and 'c' in the following format:

```javascript
{
  "epoch": EPOCH-NUMBER,
  "proof": {
      "a": "A_COORDINATE",
      "b": "B_COORDINATE",
      "c": "C_COORDINATE"
  }
}
```

### Get the current Merkle root

```bash
curl http://localhost:8080/get-commitment
```

Returns the current Merkle root as a string

```javascript
"{CURRENT_MERKLE_ROOT}";
```

### Get the current Merkle tree

```bash
curl http://localhost:8080/get-tree
```

Returns the entire current Merkle tree, starting at the root in the following format:

```javascript
{
  "Inner": {
    "hash": "ROOT_HASH",
    "is_left_sibling": false,
    "left": {
      "Inner": {
        "hash": "LEFT_CHILD_HASH",
        "is_left_sibling": true,
          "left": {
            ...
          },
          "right": {
            ...
          }
      }
    },
    "right": {
      "Inner": {
        "hash": "RIGHT_CHILD_HASH",
        "is_left_sibling": false,
        "left": {
          ...
        },
        "right": {
          ...
        }
      }
    }
  }
}
```

### Get all operations and Merkle proofs from a finanalized epoch

```bash
curl -X POST http://localhost:8080/get-epoch-operations -H "Content-Type: application/json" -d '"EPOCH"'
```

This API endpoint /get-epoch-operations accepts an epoch number and returns the previous and current commitment and a list of proofs for the specified epoch in the following format:

```javascript
{
  "epoch": "EPOCH_NUMBER",
  "previous_commitment": "PREVIOUS_COMMITMENT",
  "current_commitment": "CURRENT_COMMITMENT",
  "proofs": [
    // e.g.
    {
      "Update": [
        [ "OLD_ROOT",
          [
            { NODE_TO_PROVE },
            { FIRST_SIBLING },
            { PARENT_SIBLING },
            { ... }
          ]
        ], [
        [ "ROOT_AFTER_UPDATE",
          [
            { UPDATED_NODE_TO_PROVE },
            { FIRST_SIBLING },
            { PARENT_SIBLING },
            { ... }
          ]
        ]]
      ]}
    ]
}
```

### Get all epochs

```bash
curl http://localhost:8080/get-epochs
```

This API endpoint /get-epochs returns a sorted list of all available epochs together with the respective commitments. For each epoch, the epoch ID and the associated commitment are returned in the following form:

```javascript
{
  "epochs": [
    { "id": 0, "commitment":"COMMITMENT_EPOCH_0" },
    { "id": 1, "commitment":"COMMITMNET_EPOCH_1" },
    { "id": 2, "commitment":"COMMITMNET_EPOCH_2" }
  ]
}
```
