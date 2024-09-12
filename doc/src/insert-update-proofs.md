# Adherance to application-specific guidelines

We recall at this point that we want to prove that a specified policy has been followed, which includes, among other things, that the labels grow monotonically. Since in *Prism* only insert or update operations are allowed (i.e. one can only add new email addresses or add or revoke public keys to an existing email address), the monotonic growth of the labels should be achieved if the behavior is correct.

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

Let's start with the proof that an update operation was executed correctly, i.e. a proof-of-update. Informally speaking, an update means that the operation list (hashchain) for an already existing identifier has been updated by one operation. For example, an already existing key could be revoked or a new public key could have been added for the respective identifier. In any case, this means that another entry has been added to the hashchain in which the operations are stored.

> **Note**
> Obviously, this means that the last hash of the hashchain, which is crucial for the label-value pair in the Merkle tree, also has a new value.

The value of the leaf of the Merkle tree changes, but the index of the leaf remains the same, because it depends on the identifier (the e-mail address). When a leaf is updated, its value changes, but its position in the tree (determined by its key, e.g. the hashed email address) remains the same. This is because the key determines the position of the leaf. We know that when the input to a hash function changes, the output also changes. Since the "value" field is part of the input of the hash of the leaf, the hash of the leaf changes accordingly.
To proof the update, it is sufficient if we consider the old root (the cryptographic commitment) and perform a proof-of-membership before the value was updated, with the "old" leaf, so to say. The verification of the proof then involves performing a proof-of-membership of the leaf with the updated value and using this to calculate the new root and compare it with the current root.

In Jellyfish Merkle trees, a new version of the tree is created with each update, enabling efficient history recording while maintaining the integrity of previous states. This versioning system ensures that updates can be tracked and verified across different states of the tree and also allows reuse of unmodified parts, which helps to increase efficiency. Accordingly, when updates are made, all nodes along the updated path are given a higher version, so the verifier needs to know which version to check the update against.

## Insert Proofs

tbd

### Why uniqueness matters

> Non-membership queries are important [...] as well; otherwise, the service's dictionary might contain more than one tuple for the <bob@dom.org> label, allowing the service to show different tuples to different clients. [...] Alice can safely encrypt sensitive data using the public key the service returns for Bob.

We briefly recall what the unique identifier means and why this is important. The email addresses in Prism act as unique identifiers and in order for the service to behave correctly, it must be ensured that no email address can be inserted twice. We imagine scenarios including when the Id <bob@dom.org> appears twice or more in the dictionary:
Bob adds multiple keys and also revokes some of those keys. If there are several entries for <bob@dom.org>, scenarios are conceivable in which Bob adds a key to his first entry '<bob@dom.org>' and later has to revoke it because the corresponding private key was stolen by Oskar. Now it could happen that the revoke operation is entered in the hashchain of the second entry '<bob@dom.org>', in which the add operation of this key doesn't occur. Now when Alice goes through the operations in the first entry '<bob@dom.org>', she will find that the stolen key has not been revoked and she thinks that she can perform encryption with this key. Since a requirement of Verdict is that we rule out these scenarios (as best we can), accordingly we need to make use of Proofs-of-Non-Membership for this.

TODO: uniqueness still matters but should it be discussed somewhere here?
