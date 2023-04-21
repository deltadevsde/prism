use std::rc::Rc;
use serde::{Serialize, Deserialize};
use crypto_hash::{hex_digest, Algorithm};
use num::{BigInt, Num};
use redis::{Commands};

use crate::indexed_merkle_tree::sha256;

pub type MerkleProof = (Option<String>, Option<Vec<Node>>);
pub type UpdateProof = (MerkleProof, MerkleProof);
pub type InsertProof = (MerkleProof, UpdateProof, UpdateProof);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProofVariant {
    Update(UpdateProof),
    Insert(MerkleProof, UpdateProof, UpdateProof),
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
    pub left: Rc<Node>,
    pub right: Rc<Node>,
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
    pub const EMPTY_HASH: &'static str = "0000000000000000000000000000000000000000000000000000000000000000";
    pub const TAIL: &'static str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

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

    pub fn initialize_leaf(active: bool, is_left: bool, label: String, value: String, next: String) -> Self {
        let hash = format!("H({}, {}, {}, {})", active, label, value, next);
        let leaf = LeafNode {
            hash: sha256(&hash),
            is_left_sibling: is_left,
            active,
            value,
            label,
            next
        };
        Node::Leaf(leaf)
    }

    pub fn add_left(&mut self, left: Rc<Self>) {
        if let Node::Inner(inner) = self {
            inner.left = left;
        }
    }

    pub fn add_right(&mut self, right: Rc<Self>) {
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
                let hash = format!("H({} || {})", inner_node.left.get_hash(), inner_node.right.get_hash());
                inner_node.hash = sha256(&hash);
            }
            Node::Leaf(leaf) => {
                let hash = format!("H({}, {}, {}, {})", leaf.active, leaf.label, leaf.value, leaf.next);
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
    nodes.into_iter()
        .enumerate()
        .map(|(i, node)| {
            let is_left_sibling = i % 2 == 0;
            match node {
                Node::Inner(mut inner_node) => {
                    inner_node.is_left_sibling = is_left_sibling;
                    Node::Inner(inner_node)
                }
                Node::Leaf(mut leaf) => {
                    leaf.is_left_sibling = is_left_sibling;
                    Node::Leaf(leaf)
                }
            }
        })
        .collect()
}

impl IndexedMerkleTree {

    pub fn new(nodes: Vec<Node>) -> Self {
        let parsed_nodes = update_node_positions(nodes);

        let tree = Self { nodes: parsed_nodes };
        tree.calculate_root()
    }


    /// Create an Indexed Merkle Tree from Redis data.
    ///
    /// This function retrieves keys and values from Redis, sorts the keys based on the input order, and initializes the nodes
    /// of an Indexed Merkle Tree based on the data. It also calculates the node hashes and ensures
    /// that the tree has the correct structure (e.g. is a power of two).
    ///
    /// # Returns
    ///
    /// * An `IndexedMerkleTree` containing the nodes and structure derived from Redis data.
    pub fn create_tree_from_redis(derived_dict: &mut redis::Connection, input_order: &mut redis::Connection) -> Self {
        // Retrieve the keys from input order and sort them.
        let ordered_derived_dict_keys: Vec<String> = input_order.lrange("input_order", 0, -1).unwrap();
        let mut sorted_keys = ordered_derived_dict_keys.clone();
        sorted_keys.sort();
    
        // Initialize the leaf nodes with the value corresponding to the given key. Set the next node to the tail for now.
        let mut nodes: Vec<Node> = sorted_keys.iter().map(|key| {
            let value: String = derived_dict.get(key).unwrap(); // we retrieved the keys from the input order, so we know they exist and can get the value
            Node::initialize_leaf(true, true, key.clone(), value, Node::TAIL.to_string())
        }).collect();
        
        // calculate the next power of two, tree size is at least 8 for now
        let mut next_power_of_two: usize = 8;
        while next_power_of_two < ordered_derived_dict_keys.len() {
            next_power_of_two *= 2;
        }
        
        // Calculate the node hashes and sort the keys (right now they are sorted, so the next node is always the one bigger than the current one)
        for i in 0..nodes.len() - 1 {
            let is_next_node_active = nodes[i + 1].is_active();
            if is_next_node_active {
                let next_label = match &nodes[i + 1] {
                    Node::Leaf(next_leaf) => next_leaf.label.clone(),
                    _ => unreachable!(),
                };
            
                match &mut nodes[i] {
                    Node::Leaf(leaf) => {
                        leaf.next = next_label;
                    }
                    _ => (),
                }
            
                nodes[i].generate_hash();
            }
            
        }
        
        // resort the nodes based on the input order
        nodes.sort_by_cached_key(|node| {
            let label = match node {
                Node::Inner(_) => {
                    None
                }
                Node::Leaf(leaf) => {
                    let label = leaf.label.clone(); // get the label of the node
                    Some(label)
                }
            };
            ordered_derived_dict_keys
                .iter()
                .enumerate() // use index 
                .find(|(_, k)| {
                    *k == &label.clone().unwrap() // ohne dereferenzierung wird ein &&String mit &String verglichen
                })
                .unwrap()
                .0 // enumerate gibt tupel zurück, also index zurückgeben
        });
    
        // Add empty nodes to ensure the total number of nodes is a power of two.
        while nodes.len() < next_power_of_two {
            nodes.push(Node::initialize_leaf(false, true, Node::EMPTY_HASH.to_string(), Node::EMPTY_HASH.to_string(), Node::TAIL.to_string()));
        }
    
        // baum erstellen und dabei alle nodes überprüfen, ob sie linkes oder rechtes kind sind
        let tree = IndexedMerkleTree::new(nodes);
        tree
    }
    
    

    pub fn initialize(size: usize) -> IndexedMerkleTree {
        // ist zweierpotenz, wenn bitweise und mit n und n-1 nicht nlul ist ...
        if size & (size - 1) != 0 {
            // per code fixen (   evtl: initialize(size + 2)   )
            panic!("size must be a power of 2");
        }

        let mut tree = IndexedMerkleTree {
            nodes: Vec::new(),
        };
        for i in 0..size {
            let is_active_leaf = i == 0;
            let is_left_sibling = i % 2 == 0;
            let value = Node::EMPTY_HASH.to_string();
            let label = Node::EMPTY_HASH.to_string();
            let node = Node::initialize_leaf(is_active_leaf, is_left_sibling, value, label, Node::TAIL.to_string());
            tree.nodes.push(node);
        }

        tree.calculate_root()
    }

    fn calculate_root(mut self) -> IndexedMerkleTree {
        // first get all leaves (= nodes with no children)
        let leaves: Vec<Node> = self.nodes.clone().into_iter().filter(|node| matches!(node, Node::Leaf(_))).collect();
        // eigene nodes "resetten"
        self.nodes = leaves.clone();

        let mut parents: Vec<Node> = Vec::new();
        for (index, node) in leaves.chunks(2).enumerate() {
            let left = node[0].clone();
            let right = node.get(1).cloned().unwrap_or_else(|| left.clone());
            
            let mut new_node = Node::Inner(InnerNode {
                hash: String::from("H()"),
                is_left_sibling: index % 2 == 0,
                left: Rc::new(left),
                right: Rc::new(right),
            });
            new_node.generate_hash();
            parents.push(new_node.clone());
            self.nodes.push(new_node);
        }
        
        while parents.len() > 1 {
            let mut processed_parents: Vec<Node> = Vec::new();
            let len = parents.len();
            if len % 2 != 0 {
                // if the number is not even, we need to add the last element again
                let last_elem = parents.last().unwrap();
                parents.push(last_elem.clone());
            }

            // Für jedes Elternknotenpaar (oder einzelnen Elternknoten, falls ungerade Anzahl)
            for (index, node) in parents.chunks(2).enumerate() {
                let left = node[0].clone();
                let right = node.get(1).cloned().unwrap_or_else(|| left.clone());
                
                // Erstellen eines neuen inneren Knotens mit den gegebenen Eltern als Kinder
                let mut new_node = Node::Inner(InnerNode {
                    hash: String::from("H()"),
                    is_left_sibling: index % 2 == 0,
                    left: Rc::new(left),
                    right: Rc::new(right),
                });
                
                // Berechnen des Hashs für den neuen Knoten
                new_node.generate_hash();
                
                // Hinzufügen des neuen Knotens zur verarbeiteten Elternliste und zur Knotenliste des Baums
                self.nodes.push(new_node.clone());
                processed_parents.push(new_node);
            }
            parents = processed_parents;
        }

        // set root not as left sibling
        let root = self.nodes.last_mut().unwrap();
        root.set_left_sibling_value(false);

        self
    }

    pub fn get_root(&self) -> &Node {
        self.nodes.last().unwrap()
    } 

    pub fn get_commitment(&self) -> String {
        self.get_root().get_hash()
    }

    /* pub fn print_tree(&self) {
        // rekursiv baum printen, erst links
        fn print_node(node: &Node, indent: usize) {
            println!("{}{}", " ".repeat(indent), node.hash);
            if let Some(ref left) = node.left {
                print_node(left, indent + 2);
            }
            if let Some(ref right) = node.right {
                print_node(right, indent + 2);
            }
        }
        let root = self.get_root();
        print_node(root, 0);
    }
 */
    
    pub fn find_node_index(&self, node: &Node) -> Option<usize> {
        self.nodes.iter().enumerate().find_map(|(index, current_node)| {
            match (current_node, node) {
                (Node::Leaf(current_leaf), Node::Leaf(leaf)) => {
                    if current_leaf.label == leaf.label {
                        Some(index)
                    } else {
                        None
                    }
                },
                (Node::Inner(current_inner), Node::Inner(inner)) => {
                    if current_inner.hash == inner.hash {
                        Some(index)
                    } else {
                        None
                    }
                },
                _ => None
            }
        })
    }

    pub fn find_leaf_by_label(&self, label: &String) -> Option<Node> {
        self.nodes.iter().find_map(|node| {
            match node {
                Node::Leaf(leaf) => {
                    if &leaf.label == label {
                        Some(node.clone())
                    } else {
                        None
                    }
                },
                _ => None
            }
        })
    }


    pub fn generate_proof_of_membership(&self, index: usize) -> MerkleProof {
        // Wenn der Index außerhalb des gültigen Bereichs des Baums liegt, gibt es keinen Beweis.
        if index >= self.nodes.len() {
            return (None, None);
        }
        
        // Eine Liste mit Hashes auf dem Weg zur Wurzel als Beweis (od. Beweisliste bessergesagt)
        let mut proof: Vec<Node> = vec![];
        let mut current_index = index;
        
        // Blattknoten zur Beweisliste hinzufügen
        let leaf_node = self.nodes[current_index].clone();
        proof.push(leaf_node);
        
        // Baum hochgehen, bis zur Wurzel, und jedes Elternelement des aktuellen Knotens zur Beweisliste hinzufügen.
        while current_index < self.nodes.len() - 1 {
            // wenn der aktuelle Knoten durch 2 teilbar ist, ist es ein linker knoten, dann ist der sibling rechts (also index+1)
            let sibling_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
            let sibling_node = self.nodes[sibling_index].clone();
            proof.push(sibling_node);
            // wir müssen aufrunden, da bei 15 Elementen (8 Blättern) der Vater von index 0 mit der Berechnung 7 (bzw. 7,5) ergibt
            // der tatsächliche Vater hat aber den index 8.
            current_index = ((current_index as f64 + self.nodes.len() as f64) / 2.0).ceil() as usize;
        }
        let root = self.get_commitment();
        
        (Some(root.clone()), Some(proof))
    }

    pub fn generate_proof_of_non_membership(&self, node: &Node) -> (MerkleProof, i32) {

        // TODO: unten in der Schleife wird nicht überprüft, ob es sich um ein aktives Blatt handelt. Ich glaube aber das sollte passieren, da sonst immer ein inaktives Blatt gewählt werden könnte
        // erst nochmal überlegen, wann genau der Proof of non membership in welcher Form gebraucht wird, dann kann ich das lösen.

        // akutelle Blätter durchgehen um zu suchen, wo das neue Blatt einsortiert werden müsste
        // enumerate benutzen, um index zu bekommen
        let leaves: Vec<Node> = self.nodes.clone().into_iter().filter(|node| matches!(node, Node::Leaf(_))).collect();
        let index = leaves.iter().enumerate().find_map(|(index, current_node)| {

            let current_leaf = match current_node {
                Node::Leaf(leaf) => leaf,
                _ => unreachable!(),
            };
            let new_leaf = match node {
                Node::Leaf(leaf) => leaf,
                _ => unreachable!(),
            };

            // label und next in bigints umwandeln
            let current_label = BigInt::from_str_radix(&current_leaf.label, 16).unwrap();   
            let current_next = BigInt::from_str_radix(&current_leaf.next, 16).unwrap();
            let new_label = BigInt::from_str_radix(&new_leaf.label, 16).unwrap();

            if current_label < new_label && new_label < current_next { // funktioniert so noch nicht für ersten Hash, da müsste ich über kleiner gleich nachdenken 
                // wenn das neue label zwischen dem aktuellen label und next liegt, dann ist das der gesuchte knoten
                Some(index)
            } else {
                None // dann muss der baum verdoppelt werden, glaube ich
            }
        });

        if let Some(index) = index {
            // beweis mit gefundenem Index generieren
            (self.generate_proof_of_membership(index), index as i32)
        } else {
            ((None, None), -1)
        }

    }

    // um den proof of update durchzuführen genügt ein proof of membership mit dem alten Knoten und der alten Wurzel
    // um diesen dann zu verifizieren wird ein proof of membership mit dem neuen Knoten und der neuen Wurzel benötigt
    // zurück gegeben wird die alte wurzel, der alte beweis und die neue Wurzel und der neue Beweis
    pub fn generate_proof_of_update(mut self, index:usize, new_node: Node) -> UpdateProof {
        // alten beweis generieren
        let old_proof = self.generate_proof_of_membership(index);

        // Node updaten und neue wurzel berechnen
        self.nodes[index] = new_node;
        self = self.clone().calculate_root();

        // neuen beweis generieren
        let new_proof = self.clone().generate_proof_of_membership(index);

        // alten und neuen beweis zurückgeben
        ((old_proof), (new_proof))
    }

    // um den Proof of insert zu machen muss ich noch Gedanken machen, wie ich die Verdopplung einbauen. Vielleicht irgendwie einen bool, ob verdoppelt werden muss, da sich dann
    // ja eine ganz neue Wurzel ergibt...
    // Ansonsten: Proof of Non Membership des neuen Blattes um Eindeutigkeit zu gewährleisten...
    // dann Proof of Update mit dem Blatt, an welcher Stelle das neue Blatt eingefügt werden soll (update des next-Pointers auf neues Label)
    // zuvor leeres, ausgewähltes Blatt durch neues Blatt ersetzen, next Pointer des zuvor aktualisierten Blattes wird jetzt next Pointer des neuen Blattes und Proof of Update
    pub fn generate_proof_of_insert(&mut self, new_node: &Node) -> (MerkleProof, UpdateProof, UpdateProof) {
        // unabhängig vom ersten Schritt Proof of Non Membership, dabei index des "alten" Knotens finden
        let (proof_of_non_membership, old_index) = self.clone().generate_proof_of_non_membership(new_node);
        let index = old_index as usize;

        // ersten update beweis generieren, wobei nur vom alten Knoten an der stelle der next pointer geändert wird
        let mut new_old_node = self.nodes[index].clone();
        new_old_node.set_node_active();
        Node::update_next_pointer(&mut new_old_node, new_node);
        new_old_node.generate_hash();
        let first_update_proof = self.clone().generate_proof_of_update(index, new_old_node.clone());

        self.nodes[index] = new_old_node.clone();
        // neue wurzel berechnen
        let mut tree = self.clone().calculate_root();

        // also hier muss ich weiter machen. Der erste Beweis wird jetzt richtig erstellt, aber irgendwie wird das ursrprünglich gewählte Leaf überschrieben
        // ich glaube self wird nicht überschrieben... ich muss mir nochmal überlegen, wie ich das machen kann

        let mut new_index = None;
        for (i, node) in tree.nodes.iter_mut().enumerate() {
            if !node.is_active() {
                new_index = Some(i);
                break;
            }
        }
        let new_index = new_index.expect("Unable to find a node with a None label.");

        // zweiten update beweis generieren
        let second_update_proof = tree.generate_proof_of_update(new_index, new_node.clone());
        

        (proof_of_non_membership, first_update_proof, second_update_proof)
    }

    
    /* fn verify_merkle_proof(proof: MerkleProof, commitment: String) -> bool {
        println!("Commitment: {}", commitment);
        let path = proof.unwrap().clone();
        let mut current_hash = path[0].clone().hash;
        for i in 1..path.len() {
            let node = path[i].clone();
            let mut for_printing = String::new();
            if node.is_left_sibling.unwrap() {
                for_printing = format!("H({} || {})", &node.hash, current_hash);
                current_hash = sha256(&for_printing);
            } else {
                for_printing = format!("H({} || {})", current_hash, &node.hash);
                current_hash = sha256(&for_printing);
            }

            println!("{} = {}", for_printing, current_hash);
        }
        println!();
        current_hash == commitment
    } */

    fn verify_merkle_proof(proof: &MerkleProof) -> bool {
        match proof {
            (Some(root), Some(path)) => {
                /* println!("Commitment: {}", &root); */
                let mut current_hash = path[0].get_hash();
        
                for (_, node) in path.iter().skip(1).enumerate() {
                    let hash = if node.is_left_sibling() {
                        format!("H({} || {})", node.get_hash(), current_hash)
                    } else {
                        format!("H({} || {})", current_hash, node.get_hash())
                    };
                    current_hash = sha256(&hash);
                }
                return &current_hash == root;
            },
            _ => {
                return false;
            }
        }
    }

    pub fn verify_insert_proof(non_membership_proof: &MerkleProof, first_proof: &UpdateProof, second_proof: &UpdateProof) -> bool {
        IndexedMerkleTree::verify_merkle_proof(non_membership_proof) && IndexedMerkleTree::verify_update_proof(first_proof) && IndexedMerkleTree::verify_update_proof(second_proof)
    }
    
    pub fn verify_update_proof(proof: &UpdateProof) -> bool {
        let (old_proof, new_proof) = proof;
        IndexedMerkleTree::verify_merkle_proof(old_proof) && IndexedMerkleTree::verify_merkle_proof(new_proof)
    }


    // so kann ich gucken, ob bestellungen verändert wurden
    /* pub fn verify_tree(data: Vec<String>, root: String) -> bool {
        let tree = IndexedMerkleTree::create(data);
        let root_node = tree.get_root();
        root_node.hash == root
    }  */
}

/* #[derive(Clone)]
pub struct Dictionary {
    entries: Vec<Entry>,
} 

impl Dictionary {
    pub fn new() -> Dictionary {
        Dictionary {
            entries: Vec::new(),
        }
    }

    fn set_entry(&mut self, value: Entry) {
        self.entries.push(value);
    }

    pub fn add_entry(&mut self, key: &str, value: &str) {
        let mut chain_entry = ChainEntry {
            hash: hex_digest(Algorithm::SHA256, value.as_bytes()),
            previous_hash: "0w".to_string(),
            value: value.to_string(),
        };

        if let Some(entry) = self.entries.iter_mut().find(|e| e.key == key) {
            chain_entry.previous_hash = entry.value.last().unwrap().hash.clone();
            entry.value.push(chain_entry);
        } else {
            self.entries.push(Entry {
                key: key.to_string(),
                value: vec![chain_entry],
            });
        }
    }

    pub fn get_entry(&self, key: String) -> Option<&Vec<ChainEntry>> {
        for entry in &self.entries {
            if entry.key == key {
                return Some(&entry.value);
            }
        }

        None
    }

    pub fn print_chain(&self, key: String) {
        if let Some(chain) = self.get_entry(key.clone()) {
            for entry in chain {
                println!("{}: {}", entry.hash, entry.value);
            }
        } else {
            println!("No entry found for key {}", key);
        }
    }

    pub fn print_all(&self) {
        println!("");
        for entry in &self.entries {
            println!("{}:", entry.key);
            for chain_entry in &entry.value {
                println!("{}: {}, ({})", chain_entry.hash, chain_entry.value, chain_entry.previous_hash);
            }
            println!("");
        }
    }

    // derive a dictionary from the current dictionary
    // the key is the hashed key
    // the value is the last entry in the chain
    pub fn derive_dictionary(&self) -> Self {
        let mut dictionary = Dictionary::new();

        for entry in &self.entries {
            let hash = format!("{}", hex_digest(Algorithm::SHA256, entry.key.as_bytes()));
            dictionary.set_entry(Entry {
                key: hash,
                value: vec![entry.value.last().unwrap().clone()],
            });
        }

        dictionary
    }

}

  */
