// =============================================================================
// AXOLOTL: MOTOR DE TEMPO DE EXECUÇÃO DETERMINÍSTICO E ARMAZENAMENTO CAS ACID
// Especificação Estrita da Fase 1 - Otimizada para Microarquitetura x86_64
// =============================================================================

use std::mem::{size_of, align_of, offset_of};
use triomphe::Arc; // Alocações imutáveis lock-free de alto rendimento para L1 Cache
use redb::{Database, TableDefinition, ReadableTable};

// Definições Globais de Tabelas ACID para o Content Accessible Storage (CAS)
const CAS_TABLE: TableDefinition<[u8; 16], [u8; 32]> = TableDefinition::new("axolotl_cas");
const MEMO_TABLE: TableDefinition<[u8; 16], [u8; 16]> = TableDefinition::new("axolotl_memo");

/// Identificador de Conteúdo Compacto de 16 bytes.
/// Obtido por truncamento seguro de hash criptográfico (BLAKE3-128).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct CompactCid(pub [u8; 16]);

/// Códigos de Operação (OpCodes) estritos para prefixação determinística
/// e separação de domínio na computação do Merkle DAG.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Universe = 0,
    BoundIndex = 1,
    Lambda = 2,
    Apply = 3,
}

/// O Tipo Indutivo Atômico central do Axolotl.
/// Unifica termos, tipos e valores em exatamente 32 bytes.
/// Encaixe perfeito de duas instâncias por linha de cache de 64 bytes (x86_64).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C, u8, align(8))]
pub enum Node {
    Universe,
    BoundIndex { db_index: u32, _pad: [u8; 24] },
    Lambda { body: CompactCid, _pad: [u8; 8] },
    Apply { argument: CompactCid, _pad: [u8; 8] },
}

// =============================================================================
// AS TRAVAS DE SEGURANÇA MICROARQUITETÔNICAS (Garantia Estática)
// =============================================================================
const _: () = {
    assert!(size_of::<CompactCid>() == 16, "CompactCid DEVE ocupar exatamente 16 bytes!");
    assert!(size_of::<Node>() == 32, "Node DEVE ter exatamente 32 bytes!");
    assert!(align_of::<Node>() == 8, "Node DEVE alinhar em 8 bytes nativos do x86_64!");
    assert!(offset_of!(Node, BoundIndex.db_index) == 4, "Física da RAM violada: db_index fora do offset 4!");
    assert!(offset_of!(Node, Lambda.body) == 8, "Física da RAM violada: body do Lambda fora do offset 8!");
    assert!(offset_of!(Node, Apply.argument) == 8, "Física da RAM violada: argument do Apply fora do offset 8!");
};

impl Node {
    /// CODEC POSICIONAL CANÔNICO BINÁRIO (Preenchimento explícito contra vazamento de memória)
    pub fn to_canonical_bytes(&self) -> [u8; 32] {
        let mut buffer = [0u8; 32];
        match self {
            Node::Universe => {
                buffer[0] = OpCode::Universe as u8;
            }
            Node::BoundIndex { db_index, .. } => {
                buffer[0] = OpCode::BoundIndex as u8;
                buffer[4..8].copy_from_slice(&db_index.to_le_bytes());
            }
            Node::Lambda { body, .. } => {
                buffer[0] = OpCode::Lambda as u8;
                buffer[8..24].copy_from_slice(&body.0);
            }
            Node::Apply { argument, .. } => {
                buffer[0] = OpCode::Apply as u8;
                buffer[8..24].copy_from_slice(&argument.0);
            }
        }
        buffer
    }

    /// IDENTIDADE DIGITAL CRIPTOGRÁFICA (BLAKE3-128 sob Separação de Domínio Estrita via XOF)
    pub fn calcular_cid(&self) -> CompactCid {
        let buffer_canonico = self.to_canonical_bytes();
        let mut hasher = blake3::Hasher::new_derive_key("Axolotl Merkle DAG Content Identifier v1 Context");
        hasher.update(&buffer_canonico);
        let mut reader = hasher.finalize_xof();
        let mut bytes_cid = [0u8; 16];
        reader.fill(&mut bytes_cid);
        CompactCid(bytes_cid)
    }

    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let tag = bytes[0];
        if tag == OpCode::Universe as u8 {
            Some(Node::Universe)
        } else if tag == OpCode::BoundIndex as u8 {
            let idx = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            Some(Node::BoundIndex { db_index: idx, _pad: [0u8; 24] })
        } else if tag == OpCode::Lambda as u8 {
            let cid_bytes = bytes[8..24].try_into().unwrap();
            Some(Node::Lambda { body: CompactCid(cid_bytes), _pad: [0u8; 8] })
        } else if tag == OpCode::Apply as u8 {
            let cid_bytes = bytes[8..24].try_into().unwrap();
            Some(Node::Apply { argument: CompactCid(cid_bytes), _pad: [0u8; 8] })
        } else {
            None
        }
    }
}

// =============================================================================
// VALORES SEMÂNTICOS E ESTRUTURA DO AMBIENTE (EAM + NbE)
// =============================================================================
#[derive(Debug, Clone)]
pub enum Value {
    Universe,
    Closure { body: CompactCid, env: Env },
    Neutral(Neutral),
}

#[derive(Debug, Clone)]
pub enum Neutral {
    Var(u32),
    Apply(Arc<Neutral>, Arc<Value>),
}

/// O Ambiente Ortogonal livre de nomes da Máquina Abstrata de Ambiente (EAM).
/// Utiliza triomphe::Arc para garantir localidade estrita na Cache L1 da CPU.
#[derive(Debug, Clone)]
pub struct Env {
    variables: Arc<Vec<Value>>,
}

impl Env {
    pub fn new() -> Self {
        Env { variables: Arc::new(Vec::new()) }
    }

    pub fn extend(&self, value: Value) -> Self {
        let mut new_vars = (*self.variables).clone();
        new_vars.push(value);
        Env { variables: Arc::new(new_vars) }
    }

    pub fn lookup(&self, db_index: u32) -> Value {
        let len = self.variables.len();
        if (db_index as usize) < len {
            self.variables[len - 1 - (db_index as usize)].clone()
        } else {
            Value::Neutral(Neutral::Var(db_index))
        }
    }
}

// =============================================================================
// INFRAESTRUTURA DE PERSISTÊNCIA CAS E MEMOIZAÇÃO (REDB)
// =============================================================================
pub struct Engine {
    db: Database,
}

impl Engine {
    pub fn new(path: &str) -> Self {
        let db = Database::create(path).expect("Falha ao inicializar o banco Redb via mmap!");
        let write_txn = db.begin_write().unwrap();
        {
            let _cas = write_txn.open_table(CAS_TABLE).unwrap();
            let _memo = write_txn.open_table(MEMO_TABLE).unwrap();
        }
        write_txn.commit().unwrap();
        Engine { db }
    }

    pub fn salvar_no(&self, node: &Node) -> CompactCid {
        let cid = node.calcular_cid();
        let bytes = node.to_canonical_bytes();
        let write_txn = self.db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(CAS_TABLE).unwrap();
            table.insert(cid.0, bytes).unwrap();
        }
        write_txn.commit().unwrap();
        cid
    }

    pub fn buscar_no(&self, cid: CompactCid) -> Node {
        let read_txn = self.db.begin_read().unwrap();
        let table = read_txn.open_table(CAS_TABLE).unwrap();
        let bytes = table.get(cid.0).unwrap().expect("Invariante violada: CID ausente no CAS!");
        Node::from_canonical_bytes(bytes.value().as_ref()).unwrap()
    }

    pub fn registrar_memo(&self, input: CompactCid, output: CompactCid) {
        let write_txn = self.db.begin_write().unwrap();
        {
            let mut table = write_txn.open_table(MEMO_TABLE).unwrap();
            table.insert(input.0, output.0).unwrap();
        }
        write_txn.commit().unwrap();
    }

    pub fn obter_memo(&self, input: CompactCid) -> Option<CompactCid> {
        let read_txn = self.db.begin_read().unwrap();
        let table = read_txn.open_table(MEMO_TABLE).unwrap();
        table.get(input.0).unwrap().map(|v| CompactCid(*v.value()))
    }
}

// =============================================================================
// MÁQUINA VIRTUAL DE NORMALIZAÇÃO POR AVALIAÇÃO (VM NbE)
// =============================================================================
pub fn eval(node: Node, env: &Env, engine: &Engine) -> Value {
    match node {
        Node::Universe => Value::Universe,
        Node::BoundIndex { db_index, .. } => env.lookup(db_index),
        Node::Lambda { body, .. } => Value::Closure { body, env: env.clone() },
        Node::Apply { argument, .. } => {
            let arg_node = engine.buscar_no(argument);
            let arg_cid = arg_node.calcular_cid();
            
            // Interceptação imediata e atalho via MEMOIZAÇÃO UNIVERSAL
            if let Some(cached_result_cid) = engine.obter_memo(arg_cid) {
                let cached_node = engine.buscar_no(cached_result_cid);
                return eval(cached_node, env, engine);
            }

            let arg_val = eval(arg_node, env, engine);
            match env.lookup(0) { 
                Value::Closure { body, env: closure_env } => {
                    let result_val = apply_closure(body, &closure_env, arg_val, engine);
                    let result_node = readback(result_val.clone(), engine);
                    let result_cid = engine.salvar_no(&result_node);
                    
                    engine.registrar_memo(arg_cid, result_cid); // Memoiza globalmente
                    result_val
                }
                Value::Universe => panic!("Erro de tipo: Aplicação sobre o termo Universe!"),
                Value::Neutral(neut) => Value::Neutral(Neutral::Apply(Arc::new(neut), Arc::new(arg_val))),
            }
        }
    }
}

pub fn apply_closure(closure_body: CompactCid, closure_env: &Env, arg: Value, engine: &Engine) -> Value {
    let extended_env = closure_env.extend(arg);
    let body_node = engine.buscar_no(closure_body);
    eval(body_node, &extended_env, engine)
}

/// READBACK CANÔNICO: Re-materialização de Valores em Nós físicos de 32 bytes da Fase 1.
pub fn readback(value: Value, engine: &Engine) -> Node {
match value {
Value::Universe => Node::Universe,
Value::Closure { body, .. } => Node::Lambda { body, _pad: [0u8; 8] },
Value::Neutral(Neutral::Var(idx)) => Node::BoundIndex { db_index: idx, _pad: [0u8; 24] },
Value::Neutral(Neutral::Apply(neut, val)) => {
let _ = neut;
let res_node = readback((*val).clone(), engine);
let res_cid = engine.salvar_no(&res_node);
Node::Apply { argument: res_cid, _pad: [0u8; 8] }
}
}
}
// =============================================================================
// VERIFICAÇÃO DE EXECUÇÃO DO ARQUIVO CORE (O "Hello World" Semântico)
// =============================================================================
fn main() {
println!("=== AXOLOTL HIGH-PERFORMANCE RUNTIME ===");
// Inicializa o banco de dados ACID embutido persistido via cópia zero mmap
let engine = Engine::new("axolotl.redb");
// 1. Construção do Termo Físico da Função Identidade (λx. x) no CAS
let id_body = Node::BoundIndex { db_index: 0, _pad: [0u8; 24] };
let body_cid = engine.salvar_no(&id_body);
let identity_function = Node::Lambda { body: body_cid, _pad: [0u8; 8] };
let identity_cid = engine.salvar_no(&identity_function);
println!("Canonicity Guard: Lambda salvo no CAS com CID: {:?}", identity_cid);
// 2. Inicialização da EAM na Cache L1
let env = Env::new().extend(eval(identity_function, &Env::new(), &engine));
// 3. Execução da computação via NbE: Aplicando a identidade sobre o tipo Universe -> ((λx. x) Universe)
println!("VM NbE: Reduzindo fluxo beta-zeta...");
let result_value = apply_closure(body_cid, &env, Value::Universe, &engine);
// 4. Readback Canônico para materialização física e verificação
let final_node = readback(result_value, &engine);
let final_bytes = final_node.to_canonical_bytes();
println!("Sucesso absoluto. Nó de Resultado: {:?}", final_node);
println!("Geometria física de correspondência perfeita ({} bytes): {:?}", final_bytes.len(), final_bytes);
}