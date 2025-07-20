# Adherence to application-specific guidelines

We recall at this point that we want to prove that a specified policy has been followed, which includes, among other things, that the account's current keyset is valid given the history of addition and removal operations performed on the account.

## Versioning

JMT incorporates versioning, which is crucial for its operations. Each update to the tree creates a new version, allowing for efficient historical queries and updates. The version is part of the node key structure:

```bash
version || nibble path
```

This versioning system ensures that updates can be made efficiently without affecting previous versions of the tree.

## Insertion and Updates

The insert operation comprises three steps, which we will consider individually in the following. First, again informally: what does it mean to perform an insert operation? Insert means that we add a completely new identifier - so we add a "new" email address to our dictionary. Accordingly, when we add a value to the dictionary, the structure that supports us in any reasoning changes as well, namely our Jellyfish Merkle tree that manages the derived dictionary.

**Find the insertion position**
When traversing the tree to perform the lookup, the following two scenarios are possible:

1. A leaf node with the same prefix of the nibble path but different keyhash value is found.
2. An internal node is reached where the next nibble path to be visited (index n) contains an empty subtree.

**Handle the current node**
Once we have found the location, there are two possibilities: either it is an internal node or a leaf node.

1. if it is an internal node: a new leaf is created and inserted as a child node in the empty index n of the internal node
2. if it is a leaf node: two different scenarios can occur at this point, either KeyHash matches the key hash at the point where the previous nibble path led, in which case it is basically an update operation. Otherwise, the KeyHash values differ and a new leaf is created. In addition, new internal nodes are created to represent the common path, as both nodes match up to a certain nibble path that is not yet sufficiently represented in the tree. This internal node takes the place of the previous leaf node and then both the new and the old node (which was previously present at the split position) are inserted in the new internal node at the respective index.

**Update ancestors version**
The versions of all nodes that have been traversed along the way are then updated to the latest version.

## Proof-of-Update

The proof that an update operation was executed correctly, i.e. a proof-of-update, means that the key set for an already existing identifier has been updated by one operation correctly. For example, an already existing key could be revoked or a new public key could have been added for the respective identifier.

The value of the leaf of the Merkle tree changes, but the index of the leaf remains the same, because it depends on the identifier (e.g., an e-mail address).
To prove the update, it is sufficient if we consider the previous state root (the cryptographic commitment) and perform a proof-of-membership before the value was updated, with the "old" leaf. The verification of the proof then involves performing a proof-of-membership of the leaf with the updated value and using this to calculate the new root and compare it with the current root.

In Jellyfish Merkle trees, a new version of the tree is created with each update, enabling efficient history recording while maintaining the integrity of previous states. This versioning system ensures that updates can be tracked and verified across different states of the tree and also allows reuse of unmodified parts, which helps to increase efficiency. Accordingly, when updates are made, all nodes along the updated path are given a higher version, so the verifier needs to know which version to check the update against.

## Proof-of-Insert

Insertion proofs consist of the inserted key, a non-membership proof of the node in the current tree, a membership proof of the new node in the JMT, and the updated merkle root.

The non-inclusion proof has two variants for different cases:

1. A leaf exists where the missing leaf *should* be, sharing a prefix with the key (recall that the path to the leaf is determined by the key bytes, and paths get compressed for efficiency)
2. The node key leads to an empty subtree

After finding the position the new node should be inserted into, it is inserted and a membership proof is created.

Verification of update proofs is pretty self explanatory -- The non-inclusion proof is verified against the current state root, then the insertion is carried out locally to test that the membership proof leads to the same new root.
