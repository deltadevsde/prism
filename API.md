It makes sense and is necessary to build different frontends in order to use the transparency dictionaries. In the following section, we will provide a brief overview of the most important interfaces for interacting with Deimos.

### Update the Dictionary

The update operation causes either the hashchain for an existing entry to be updated (i.e. an entry is added to the hashchain) or, if the ID does not yet exist, it's added as a new ID to the Transparency Dictionary and the associated value is the first and last value of the associated hashchain to date.

```bash
curl -X POST http://localhost:8080/update-entry \
      -H "Content-Type: application/json" \
      -d '{ "public_key": "YOUR_PUBLIC_KEY", \
            "signed_message": "YOUR_SIGNED_MESSAGE"}'
```

### Get the current Merkle root

```bash
curl http://localhost:8080/get-current-commitment
```

Returns the current Merkle root as a string

```javascript
"{CURRENT_MERKLE_ROOT}";
```

### Get valid keys for a user

The /get-valid-keys endpoint calculates the non-revoked values associated with an ID.

```bash
curl -X POST http://localhost:8080/get-valid-keys \
      -H "Content-Type: application/json" \
      -d '{
            "id": "YOUR_ID"
          }'
```

 The function retrieves the hashchain associated with the provided ID from the database. It then iterates through the hashchain to find all
 the non-revoked keys. The resulting list of non-revoked keys is returned as a JSON object like the following:

 ```javascript
{
  "values": [public_key1, public_key2, ...]
}
 ```

If the ID is not found in the database, the endpoint will return a BadRequest response with the message "Could not calculate values".
