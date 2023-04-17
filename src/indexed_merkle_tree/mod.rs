//TODO: REFACTORING!
use serde::{Serialize, Deserialize};
use crypto_hash::{hex_digest, Algorithm};
use num::{BigInt, Num};
use redis::{Commands};

pub type MerkleProof = (Option<String>, Option<Vec<Node>>);
pub type UpdateProof = (MerkleProof, MerkleProof);
pub type InsertProof = (MerkleProof, MerkleProof, MerkleProof);

pub struct Proof {
    pub old_root: String,
    pub old_path: Vec<Node>,
    pub new_root: String,
    pub new_path: Vec<Node>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Node {
    pub hash: String, // for nodes and leafes
    pub is_left_sibling: Option<bool>, // for nodes and leafes
    pub left: Option<Box<Node>>, // for nodes only 
    pub right: Option<Box<Node>>, // for nodes only
    pub active: Option<Box<bool>>, // for leafes only
    pub value: Option<Box<String>>, // for leafes only
    pub label: Option<Box<String>>, // for leafes labels, for nodes hashes of left and right child
    pub next: Option<Box<String>>, // for leafes only
}

impl Clone for Node {
    fn clone(&self) -> Self {
        Node {
            hash: self.hash.clone(),
            is_left_sibling: self.is_left_sibling.clone(),
            left: self.left.clone(),
            right: self.right.clone(),
            active: self.active.clone(),
            value: self.value.clone(),
            label: self.label.clone(),
            next: self.next.clone(),
        }
    }
}

pub fn sha256(input: &String) -> String {
    hex_digest(Algorithm::SHA256, input.as_bytes())
}

impl Node {
    pub fn new(hash: String) -> Node {
        Node {
            hash,
            is_left_sibling: Some(true),
            left: None,
            right: None,
            active: None,
            value: None,
            label: None,
            next: None,
        }
    }

    pub fn create_first_node() -> Node {
        let empty_hash = Node::create_empty_hash();
        let tail = Node::create_tail();
        Node::initialize_leaf(true, true, empty_hash.clone(), empty_hash, tail)
    }

    pub fn create_empty_hash() -> String {
        "0".repeat(64).to_string()
    }

    pub fn create_tail() -> String {
        "F".repeat(64).to_string()
    }

    pub fn initialize_leaf(active: bool, is_left: bool, label: String, value: String, next: String) -> Self {
        let hash = format!("H({}, {}, {}, {})", active, label, value, next);
        let mut node = Node::new(sha256(&hash));
        node.is_left_sibling = Some(is_left);
        node.active = Some(Box::new(active));
        node.value = Some(Box::new(value));
        node.label = Some(Box::new(label));
        node.next = Some(Box::new(next));
        node
    }

    pub fn add_left(&mut self, left: Node) -> &mut Self {
        self.left = Some(Box::new(left));
        self
    }

    pub fn add_right(&mut self, right: Node) -> &mut Self {
        self.right = Some(Box::new(right));
        self
    }

    pub fn calculate_node_hash(mut self) -> Self {
        let hash = format!("H({:?}, {:?}, {:?}, {:?})", self.active, self.label, self.value, self.next);
        self.hash = sha256(&hash);
        self
    }

    pub fn generate_hash(&mut self) -> &mut Node {
        if let Some(left) = &self.left {
            let left_hash = &left.hash;
            // wenn rechter knoten existiert, dann hash von rechtem knoten, sonst hash von linkem knoten
            let right_hash = &self.right.as_ref().map_or(left_hash, |r| &r.hash); 
            let hash = format!("H({} || {})", left_hash, right_hash);
            self.label = Some(Box::new(hash.clone()));
            self.hash = sha256(&hash);
        }
        self
    }
}

#[derive(Serialize, Deserialize)]
pub struct IndexedMerkleTree {
    nodes: Vec<Node>,
}

impl Clone for IndexedMerkleTree {
    fn clone(&self) -> Self {
        IndexedMerkleTree {
            nodes: self.nodes.clone(),
        }
    }
}

impl IndexedMerkleTree {

    pub fn new(nodes: Vec<Node>) -> Self {
        let mut tree = Self {
            nodes,
        };
        tree.nodes.iter_mut().enumerate().for_each(|(i, node)| {
            node.is_left_sibling = Some(i % 2 == 0);
        });
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
            Node::initialize_leaf(true, true, key.clone(), value, Node::create_tail())
        }).collect();
        
        // calculate the next power of two, tree size is at least 8 for now
        let mut next_power_of_two: usize = 8;
        while next_power_of_two < ordered_derived_dict_keys.len() {
            next_power_of_two *= 2;
        }
        
        // Calculate the node hashes and sort the keys (right now they are sorted, so the next node is always the one bigger than the current one)
        for i in 0..nodes.len() - 1 {
            let is_next_node_active = nodes[i + 1].active.as_deref().unwrap();
            if is_next_node_active == &true {
                nodes[i].next = nodes[i + 1].label.clone();
                nodes[i] = nodes[i].clone().calculate_node_hash();
            }
        }
        
        // resort the nodes based on the input order
        nodes.sort_by_cached_key(|node| {
            let label = node.label.as_deref().unwrap(); // get the label of the node

            ordered_derived_dict_keys
                .iter()
                .enumerate() // use index 
                .find(|(_, k)| {
                    *k == label // ohne dereferenzierung wird ein &&String mit &String verglichen
                })
                .unwrap()
                .0 // enumerate gibt tupel zurück, also index zurückgeben
        });
    
        // Add empty nodes to ensure the total number of nodes is a power of two.
        while nodes.len() < next_power_of_two {
            let empty_hash = Node::create_empty_hash();
            nodes.push(Node::initialize_leaf(false, true, empty_hash.clone(), empty_hash, Node::create_tail()));
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
            let value = Node::create_empty_hash();
            let label = Node::create_empty_hash();
            let node = Node::initialize_leaf(is_active_leaf, is_left_sibling, value, label, Node::create_tail());
            tree.nodes.push(node);
        }

        tree.calculate_root()
    }

    fn calculate_root(mut self) -> IndexedMerkleTree {
        // first get all leaves (= nodes with no children)
        let leaves: Vec<Node> = self.nodes.clone().into_iter().filter(|node| node.left.is_none()).collect();
        // eigene nodes "resetten"
        self.nodes = leaves.clone();

        let mut parents: Vec<Node> = Vec::new();
        for (index, node) in leaves.chunks(2).enumerate() {
            let mut new_node = Node::new(format!("H()"));
            new_node.is_left_sibling = Some(index % 2 == 0);
            new_node.add_left(node[0].clone());
            new_node.add_right(node[1].clone());
            
            new_node.generate_hash();

            parents.push(new_node.clone());
            self.nodes.push(new_node);
        }
        
        while parents.len() > 1 {
            let mut processed_parents: Vec<Node> = Vec::new();
            let len = parents.len();
            if len % 2 != 0 {
                let last_elem = parents.last().unwrap(); // füge letztes element nochmal hinzu, wenn anzahl ungerade
                let last_as_leaf = Node::new(last_elem.hash.clone());
                parents.push(last_as_leaf);
            }

            for (index, node) in parents.chunks(2).enumerate() {
                let mut new_node = Node::new(format!("H()"));
                new_node.is_left_sibling = Some(index % 2 == 0);
                new_node.add_left(node[0].clone());
                new_node.add_right(node[1].clone());
                
                new_node.generate_hash();
            
               
            
                self.nodes.push(new_node.clone());
                processed_parents.push(new_node);
            }
            parents = processed_parents;
        }

        // set root not as left sibling
        let root = self.nodes.last_mut().unwrap();
        root.is_left_sibling = None;

        self
    }

    pub fn get_root(&self) -> &Node {
        self.nodes.last().unwrap()
    } 

    pub fn get_commitment(&self) -> String {
        self.get_root().hash.clone()
    }

    pub fn print_tree(&self) {
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

    pub fn find_node_index(&self, node: Node) -> Option<usize> {
        self.nodes.iter().enumerate().find_map(|(index, current_node)| {
            if current_node.label == node.label {
                Some(index)
            } else {
                None
            }
        })
    }

    pub fn find_leaf_by_label(&self, label: &String) -> Option<Node> {
        self.nodes.iter().find_map(|node| {
            if node.label == Some(Box::new(label.clone())) {
                Some(node.clone())
            } else {
                None
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
        
        (Some(root), Some(proof))
    }

    pub fn generate_proof_of_non_membership(&self, node: Node) -> (MerkleProof, i32) {

        // TODO: unten in der Schleife wird nicht überprüft, ob es sich um ein aktives Blatt handelt. Ich glaube aber das sollte passieren, da sonst immer ein inaktives Blatt gewählt werden könnte
        // erst nochmal überlegen, wann genau der Proof of non membership in welcher Form gebraucht wird, dann kann ich das lösen.

        // akutelle Blätter durchgehen um zu suchen, wo das neue Blatt einsortiert werden müsste
        // enumerate benutzen, um index zu bekommen
        let leaves: Vec<Node> = self.nodes.clone().into_iter().filter(|node| node.left.is_none()).collect();
        let index = leaves.iter().enumerate().find_map(|(index, current_node)| {
            // label und next in bigints umwandeln
            let current_label = BigInt::from_str_radix(&current_node.clone().label.unwrap(), 16).unwrap();   
            let current_next = BigInt::from_str_radix(&current_node.clone().next.unwrap(), 16).unwrap();
            let new_label = BigInt::from_str_radix(&node.clone().label.unwrap(), 16).unwrap();

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
    pub fn generate_proof_of_insert(&mut self, new_node: Node) -> (MerkleProof, UpdateProof, UpdateProof) {
        // unabhängig vom ersten Schritt Proof of Non Membership, dabei index des "alten" Knotens finden
        let (proof_of_non_membership, old_index) = self.clone().generate_proof_of_non_membership(new_node.clone());
        let index = old_index as usize;

        // ersten update beweis generieren, wobei nur vom alten Knoten an der stelle der next pointer geändert wird
        let mut new_old_node = self.nodes[index].clone();
        new_old_node.active = Some(Box::new(true));
        new_old_node.next = Some(new_node.clone().label.unwrap());
        let new_old_node = new_old_node.calculate_node_hash();
        let first_update_proof = self.clone().generate_proof_of_update(index, new_old_node.clone());

        self.nodes[index] = new_old_node.clone();
        // neue wurzel berechnen
        let mut tree = self.clone().calculate_root();

        // also hier muss ich weiter machen. Der erste Beweis wird jetzt richtig erstellt, aber irgendwie wird das ursrprünglich gewählte Leaf überschrieben
        // ich glaube self wird nicht überschrieben... ich muss mir nochmal überlegen, wie ich das machen kann

        let mut new_index = None;
        for (i, node) in tree.nodes.iter_mut().enumerate() {
            if node.active == Some(Box::new(false)) {
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

    fn verify_merkle_proof(proof: MerkleProof) -> bool {
        
        match proof {
            (Some(root), Some(path)) => {
                /* println!("Commitment: {}", &root); */
                let mut current_hash = path[0].hash.clone();
    
                for (_, node) in path.iter().skip(1).enumerate() {
                    let hash = if node.is_left_sibling.unwrap() {
                        format!("H({} || {})", node.hash, current_hash)
                    } else {
                        format!("H({} || {})", current_hash, node.hash)
                    };
                    current_hash = sha256(&hash);
                    /* println!("{} = {}", hash, current_hash); */
                }
            
                /* println!(); */

                return current_hash == root;
            },
            _ => {
                return false;
            }
        }
    }

    pub fn verify_insert_proof(non_membership_proof: MerkleProof, first_proof: UpdateProof, second_proof: UpdateProof) -> bool {
        IndexedMerkleTree::verify_merkle_proof(non_membership_proof) && IndexedMerkleTree::verify_update_proof(first_proof) && IndexedMerkleTree::verify_update_proof(second_proof)
    }
    
    pub fn verify_update_proof(proof: UpdateProof) -> bool {
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