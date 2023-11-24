use crypto_hash::{hex_digest, Algorithm};
use num::{BigInt, Num};
use redis::Commands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::MerkleTreeError;

pub type MerkleProof = (Option<String>, Option<Vec<Node>>);
pub type UpdateProof = (MerkleProof, MerkleProof);
pub type InsertProof = (MerkleProof, UpdateProof, UpdateProof);

pub fn sha256(input: &String) -> String {
    hex_digest(Algorithm::SHA256, input.as_bytes())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProofVariant {
    Update(UpdateProof),
    Insert(InsertProof),
}

pub struct Proof {
    pub old_root: String,
    pub old_path: Vec<Node>,
    pub new_root: String,
    pub new_path: Vec<Node>,
}

// Separate structures for InnerNode and Leaf
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InnerNode {
    pub hash: String,
    pub is_left_sibling: bool,
    pub left: Arc<Node>,
    pub right: Arc<Node>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeafNode {
    pub hash: String,
    pub is_left_sibling: bool,
    pub active: bool,
    pub value: String,
    pub label: String,
    pub next: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Node {
    Inner(InnerNode),
    Leaf(LeafNode),
}

impl Node {
    pub const EMPTY_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    pub const TAIL: &'static str =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    pub fn get_hash(&self) -> String {
        match self {
            Node::Inner(inner_node) => inner_node.hash.clone(),
            Node::Leaf(leaf) => leaf.hash.clone(),
        }
    }

    pub fn is_left_sibling(&self) -> bool {
        match self {
            Node::Inner(inner_node) => inner_node.is_left_sibling,
            Node::Leaf(leaf) => leaf.is_left_sibling,
        }
    }

    pub fn is_active(&self) -> bool {
        match self {
            Node::Inner(_) => true,
            Node::Leaf(leaf) => leaf.active,
        }
    }

    pub fn set_left_sibling_value(&mut self, is_left: bool) {
        match self {
            Node::Inner(inner_node) => inner_node.is_left_sibling = is_left,
            Node::Leaf(leaf) => leaf.is_left_sibling = is_left,
        }
    }

    pub fn set_node_active(&mut self) {
        match self {
            Node::Inner(_) => (),
            Node::Leaf(ref mut leaf) => leaf.active = true,
        }
    }

    pub fn initialize_leaf(
        active: bool,
        is_left: bool,
        label: String,
        value: String,
        next: String,
    ) -> Self {
        let hash = format!("H({}, {}, {}, {})", active, label, value, next);
        let leaf = LeafNode {
            hash: sha256(&hash),
            is_left_sibling: is_left,
            active,
            value,
            label,
            next,
        };
        Node::Leaf(leaf)
    }

    pub fn add_left(&mut self, left: Arc<Self>) {
        if let Node::Inner(inner) = self {
            inner.left = left;
        }
    }

    pub fn add_right(&mut self, right: Arc<Self>) {
        if let Node::Inner(inner) = self {
            inner.right = right;
        }
    }

    pub fn update_next_pointer(new_old_node: &mut Self, new_node: &Self) {
        if let Self::Leaf(ref mut leaf) = new_old_node {
            if let Self::Leaf(new_leaf) = new_node {
                leaf.next = new_leaf.label.clone();
            }
        }
    }

    pub fn generate_hash(&mut self) {
        match self {
            Node::Inner(inner_node) => {
                let hash = format!(
                    "H({} || {})",
                    inner_node.left.get_hash(),
                    inner_node.right.get_hash()
                );
                inner_node.hash = sha256(&hash);
            }
            Node::Leaf(leaf) => {
                let hash = format!(
                    "H({}, {}, {}, {})",
                    leaf.active, leaf.label, leaf.value, leaf.next
                );
                leaf.hash = sha256(&hash);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IndexedMerkleTree {
    nodes: Vec<Node>,
}

pub fn update_node_positions(nodes: Vec<Node>) -> Vec<Node> {
    nodes
        .into_iter()
        .enumerate()
        .map(|(i, mut node)| {
            let is_left_sibling = i % 2 == 0;
            node.set_left_sibling_value(is_left_sibling);
            node
        })
        .collect()
}

impl IndexedMerkleTree {
    /// Creates a new `IndexedMerkleTree` from a given `nodes` vector.
    ///
    /// # Arguments
    ///
    /// * `nodes` - A vector of nodes from which the Merkle tree will be built.
    ///
    /// # Returns
    ///
    /// * `Self` - A new IndexedMerkleTree
    pub fn new(nodes: Vec<Node>) -> Result<Self, MerkleTreeError> {
        let parsed_nodes = update_node_positions(nodes);

        let tree = Self {
            nodes: parsed_nodes,
        };
        Ok(tree.calculate_root()?)
    }

    pub fn calculate_empty_tree_commitment_from_site(size: usize) -> Result<String, MerkleTreeError> {
        let mut nodes: Vec<Node> = Vec::new();

        for i in 0..size {
            let is_active_leaf = i == 0;
            let is_left_sibling = i % 2 == 0;
            let value = Node::EMPTY_HASH.to_string();
            let label = Node::EMPTY_HASH.to_string();
            let node = Node::initialize_leaf(
                is_active_leaf,
                is_left_sibling,
                value,
                label,
                Node::TAIL.to_string(),
            );
            nodes.push(node);
        }

        let tree = IndexedMerkleTree::new(nodes)?;
        tree.get_commitment()
    }

    pub fn resort_nodes_by_input_order(
        mut nodes: Vec<Node>,
        input_order: &mut redis::Connection,
    ) -> Result<Vec<Node>, MerkleTreeError> {
        // TODO: shouldnt be redis specific, has to be a Vec<String> Argument, thats why i wont "fix" the unwrap here
        let ordered_derived_dict_keys: Vec<String> =
            input_order.lrange("input_order", 0, -1).unwrap();

        let valid_nodes: Vec<_> = nodes.into_iter()
            .filter_map(|node| { // we dont want to sort directly, when we only sort valid nodes so we dont have to handle results in the sorting function
                let label = match &node {
                    Node::Inner(_) => None,
                    Node::Leaf(leaf) => Some(leaf.label.clone()),
                };
    
                // if there is a valid label search for the index in the ordered_derived_dict_keys and return it with the node
                label.and_then(|l| {
                    ordered_derived_dict_keys.iter().position(|k| k == &l)
                        .map(|index| (index, node))
                })
            })
            .collect();
    
        let mut sorted_nodes = valid_nodes;
        sorted_nodes.sort_by_key(|(index, _)| index); // sort by the index
        let sorted_nodes = sorted_nodes.into_iter().map(|(_, node)| node).collect(); // remove the index from the tuple, we want the list of nodes
    
        Ok(sorted_nodes)
    }

    pub fn create_inner_node(left: Node, right: Node, index: usize) -> Node {
        let mut new_node = Node::Inner(InnerNode {
            hash: String::from("H()"),
            is_left_sibling: index % 2 == 0,
            left: Arc::new(left),
            right: Arc::new(right),
        });
        new_node.generate_hash();
        new_node
    }

    /// Calculates the next level of the Merkle tree by aggregating the hash values of the
    /// current level nodes in pairs, creating new inner nodes and adding them to the indexed merkle tree nodes.
    ///
    /// # Arguments
    ///
    /// * `current_nodes` - A vector of nodes representing the current level of the tree.
    ///
    /// # Returns
    ///
    /// A vector of nodes representing the next level of the Merkle tree.
    pub fn calculate_next_level(&mut self, current_nodes: Vec<Node>) -> Vec<Node> {
        let mut next_level_nodes: Vec<Node> = Vec::new();

        for (index, node) in current_nodes.chunks(2).enumerate() {
            let new_node =
                IndexedMerkleTree::create_inner_node(node[0].clone(), node[1].clone(), index);
            next_level_nodes.push(new_node.clone());
            self.nodes.push(new_node);
        }

        next_level_nodes
    }

    /// Calculates the root of an IndexedMerkleTree by aggregating the tree's nodes.
    ///
    /// The function performs the followig (main) steps:
    /// 1. Extracts all the leaf nodes from the tree.
    /// 2. Resets the tree's nodes to the extracted leaves.
    /// 3. Iteratively constructs parent nodes from pairs of child nodes until there is only one node left (the root).
    ///
    /// # Arguments
    ///
    /// * `self` - The mutable reference to the IndexedMerkleTree instance.
    ///
    /// # Returns
    ///
    /// * `IndexedMerkleTree` - The updated IndexedMerkleTree instance with the calculated root.
    fn calculate_root(mut self) -> Result<IndexedMerkleTree, MerkleTreeError> {
        // first get all leaves (= nodes with no children)
        let leaves: Vec<Node> = self
            .nodes
            .clone()
            .into_iter()
            .filter(|node| matches!(node, Node::Leaf(_)))
            .collect();
        // "reset" own nodes
        self.nodes = leaves.clone();

        let mut parents: Vec<Node> = self.calculate_next_level(leaves);

        while parents.len() > 1 {
            let processed_parents: Vec<Node> = self.calculate_next_level(parents);
            parents = processed_parents;
        }

        // set root not as left sibling
        let root = self.nodes.last_mut().ok_or(MerkleTreeError::EmptyMerkleTreeError)?; // TODO: are there possible other Errors? is it possible at all to have an empty tree at this point?
        root.set_left_sibling_value(false);

        Ok(self)
    }

    /// # Returns
    ///
    /// The current root node of the Indexed Merkle tree.
    pub fn get_root(&self) -> Result<&Node, MerkleTreeError> {
        self.nodes.last().ok_or(MerkleTreeError::EmptyMerkleTreeError)
    }

    /// # Returns
    ///
    /// The current commitment (hash of the root node) of the Indexed Merkle tree.
    pub fn get_commitment(&self) -> Result<String, MerkleTreeError> {
        Ok(self.get_root()?.get_hash()) 
    }

    // TODO: is it better to return a Result here and in the next function?
    pub fn find_node_index(&self, node: &Node) -> Option<usize> {
        self.nodes
            .iter()
            .enumerate()
            .find_map(|(index, current_node)| match (current_node, node) {
                (Node::Leaf(current_leaf), Node::Leaf(leaf)) => {
                    if current_leaf.label == leaf.label {
                        Some(index)
                    } else {
                        None
                    }
                }
                (Node::Inner(current_inner), Node::Inner(inner)) => {
                    if current_inner.hash == inner.hash {
                        Some(index)
                    } else {
                        None
                    }
                }
                _ => None,
            })
    }

    pub fn find_leaf_by_label(&self, label: &String) -> Option<Node> {
        self.nodes.iter().find_map(|node| match node {
            Node::Leaf(leaf) => {
                if &leaf.label == label {
                    Some(node.clone())
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    pub fn generate_proof_of_membership(&self, index: usize) -> Result<MerkleProof, MerkleTreeError> {
        // if the index is outside of the valid range of the tree, there is no proof
        if index >= self.nodes.len() {
            return Err(MerkleTreeError::IndexError(index.to_string()));
        }

        // create a vec with hashes on the way to the root as proof (proof-list so to say)
        let mut proof_path: Vec<Node> = vec![];
        let mut current_index = index;

        // add the leaf node itself to the proof list
        let leaf_node = self.nodes[current_index].clone();
        proof_path.push(leaf_node);

        // climb the tree until we reach the root and add each parent node sibling of the current node to the proof list
        while current_index < self.nodes.len() - 1 {
            // if the current node is divisible by 2, it is a left node, then the sibling is right (index + 1) and vice versa
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling_node = self.nodes[sibling_index].clone();
            proof_path.push(sibling_node);
            // we have to round up, because if there are e.g. 15 elements (8 leaves) the parent of index 0 would be 7 (or 7.5)
            // but the actual parent of index 0 is 8
            current_index =
                ((current_index as f64 + self.nodes.len() as f64) / 2.0).ceil() as usize;
        }
        let root = self.get_commitment()?;

        Ok((Some(root.clone()), Some(proof_path)))
    }

    pub fn generate_non_membership_proof(&self, node: &Node) -> Result<(MerkleProof, Option<usize>), MerkleTreeError> {
        let given_node_as_leaf = match node {
            Node::Leaf(leaf) => leaf,
            _ => return Err(MerkleTreeError::NotFoundError(format!("Leaf"))),
        };
    
        let mut found_index = None;
        for (index, current_node) in self.nodes.iter().enumerate() {
            if let Node::Leaf(current_leaf) = current_node {
                let current_label = BigInt::from_str_radix(&current_leaf.label, 16);
                let current_next = BigInt::from_str_radix(&current_leaf.next, 16);
                let new_label = BigInt::from_str_radix(&given_node_as_leaf.label, 16);
    
                if let (Ok(current_label), Ok(current_next), Ok(new_label)) = (current_label, current_next, new_label) {
                    if current_label < new_label && new_label < current_next {
                        found_index = Some(index);
                        break;
                    }
                } else {
                    return Err(MerkleTreeError::InvalidFormatError(format!("BigInt from label or next pointer")));
                }
            }
        }
    
        match found_index {
            Some(index) => Ok((self.generate_proof_of_membership(index)?, Some(index))),
            None => Err(MerkleTreeError::MerkleProofError),
        }
    }

    // to perform the proof of update a proof of membership with the old node and the old root is sufficient
    // to verify this a membership proof of the new node and new root is needed
    // the old root, the old proof, the new root and the new proof are returned
    pub fn generate_update_proof(mut self, index: usize, new_node: Node) -> Result<(UpdateProof, Self), MerkleTreeError> {
        // generate old proof
        let old_proof = self.generate_proof_of_membership(index)?;

        // update node and calculate new root
        self.nodes[index] = new_node;
        self = self.clone().calculate_root()?;

        // generate new proof
        let new_proof = self.clone().generate_proof_of_membership(index)?;

        // return old and new proof
        Ok(((old_proof, new_proof), self))
    }

    pub fn generate_proof_of_insert(
        &mut self,
        new_node: &Node,
    ) -> Result<(MerkleProof, UpdateProof, UpdateProof), MerkleTreeError> {
        // perform non-membership check in order to return the index of the node to be changed
        let (proof_of_non_membership, old_index) =
            self.clone().generate_non_membership_proof(new_node)?;

        if old_index.is_none() {
            return Err(MerkleTreeError::MerkleProofError);
        }

        // we know that the index is valid, so we can unwrap it
        let old_index = old_index.unwrap();

        // generate first update proof, changing only the next pointer from the old node
        let mut new_old_node = self.nodes[old_index].clone();
        Node::update_next_pointer(&mut new_old_node, new_node);
        new_old_node.generate_hash();
        let (first_update_proof, updated_self) = self
            .clone()
            .generate_update_proof(old_index, new_old_node.clone())?;

        *self = updated_self;

        // we checked if the found index in the non-membership is from an incative node, if not we have to search for another inactive node to update and if we cant find one, we have to double the tree
        let mut new_index = None;
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if !node.is_active() {
                new_index = Some(i);
                break;
            }
        }
        let new_index = new_index.expect("Unable to find an inactive node.");

        // generate second update proof
        let (second_update_proof, updated_self) = self
            .clone()
            .generate_update_proof(new_index, new_node.clone())?;

        *self = updated_self;

        Ok((
            proof_of_non_membership,
            first_update_proof,
            second_update_proof,
        ))
    }

    fn verify_merkle_proof(proof: &MerkleProof) -> bool {
        match proof {
            (Some(root), Some(path)) => {
                // save the first now as current hash and skip it in the loop to start with the second
                let mut current_hash = path[0].get_hash();

                for node in path.iter().skip(1) {
                    let hash = if node.is_left_sibling() {
                        format!("H({} || {})", node.get_hash(), current_hash)
                    } else {
                        format!("H({} || {})", current_hash, node.get_hash())
                    };
                    current_hash = sha256(&hash);
                }
                return &current_hash == root;
            }
            _ => false,
        }
    }

    pub fn verify_update_proof((old_proof, new_proof): &UpdateProof) -> bool {
        IndexedMerkleTree::verify_merkle_proof(old_proof)
            && IndexedMerkleTree::verify_merkle_proof(new_proof)
    }

    pub fn verify_insert_proof(
        non_membership_proof: &MerkleProof,
        first_proof: &UpdateProof,
        second_proof: &UpdateProof,
    ) -> bool {
        IndexedMerkleTree::verify_merkle_proof(non_membership_proof)
            && IndexedMerkleTree::verify_update_proof(first_proof)
            && IndexedMerkleTree::verify_update_proof(second_proof)
    }
}
