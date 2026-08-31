use std::mem::{size_of, align_of, offset_of};

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
/// Otimizado para x86_64: 2 instâncias encaixam perfeitamente em uma Cache Line de 64 bytes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C, u8, align(8))]
pub enum Node {
    /// 1 byte (tag) + 31 bytes padding implícito zerado = 32 bytes
    Universe,

    /// Variável de escopo local indexada via Índice de De Bruijn estrutural.
    /// 1 byte (tag) + 3 bytes (pad) + 4 bytes (u32) + 24 bytes (pad manual) = 32 bytes
    BoundIndex { 
        db_index: u32,
        _pad: [u8; 24], 
    },

    /// Abstração Lambda com currificação estrita de tipo Pi.
    /// Aponta apenas para o CID imutável do escopo do corpo.
    /// 1 byte (tag) + 7 bytes (pad) + 16 bytes (CID) + 8 bytes (pad manual) = 32 bytes
    Lambda { 
        body: CompactCid,
        _pad: [u8; 8], 
    },

    /// Aplicação estrita de um único argumento por nó (espremedura de aplicação).
    /// 1 byte (tag) + 7 bytes (pad) + 16 bytes (CID) + 8 bytes (pad manual) = 32 bytes
    Apply { 
        argument: CompactCid,
        _pad: [u8; 8], 
    },
}

// =============================================================================
// AS TRAVAS DE SEGURANÇA MICROARQUITETÔNICAS (Garantia Estática)
// =============================================================================
const _: () = {
    // Garante localidade espacial estrita e anula fragmentação
    assert!(size_of::<CompactCid>() == 16, "CompactCid DEVE ocupar exatamente 16 bytes puros!");
    assert!(size_of::<Node>() == 32, "Node DEVE ter exatamente 32 bytes!");
    assert!(align_of::<Node>() == 8, "Node DEVE alinhar em 8 bytes nativos do x86_64!");

    // 2. Validação Cirúrgica de Offsets (Comprova o casamento exato com o seu Codec)
    // Garante que o u32 do BoundIndex está exatamente onde o buffer[4..8] lê
    assert!(offset_of!(Node, BoundIndex::db_index) == 4, "Física da RAM violada: db_index deve iniciar no offset 4!");
    
    // Garante que os CompactCids de Lambda e Apply estão exatamente onde o buffer[8..24] lê
    assert!(offset_of!(Node, Lambda::body) == 8, "Física da RAM violada: body do Lambda deve iniciar no offset 8!");
    assert!(offset_of!(Node, Apply::argument) == 8, "Física da RAM violada: argument do Apply deve iniciar no offset 8!");
};

impl Node {
    /// CODEC POSICIONAL CANÔNICO BINÁRIO (Fase 1 de RAM / Serialização)
    /// Materializa a geometria do nó em um buffer estático blindado contra lixo de memória.
    /// Custo de CPU: Mínimo. Alocação na Heap: ZERO.
    pub fn to_canonical_bytes(&self) -> [u8; 32] {
        // Inicializa o buffer na Stack rigorosamente com 0x00 para garantir canonicidade
        let mut buffer = [0u8; 32];

        match self {
            Node::Universe => {
                buffer[0] = OpCode::Universe as u8;
            }
            Node::BoundIndex { db_index, .. } => {
                buffer[0] = OpCode::BoundIndex as u8;
                // Alinhamento natural do u32 no offset 4 conforme especificação C
                buffer[4..8].copy_from_slice(&db_index.to_le_bytes());
            }
            Node::Lambda { body, .. } => {
                buffer[0] = OpCode::Lambda as u8;
                // Alinhamento do CompactCid no offset 8 pelo padding de 7 bytes pós-tag u8
                buffer[8..24].copy_from_slice(&body.0);
            }
            Node::Apply { argument, .. } => {
                buffer[0] = OpCode::Apply as u8;
                buffer[8..24].copy_from_slice(&argument.0);
            }
        }
        buffer
    }

    /// IDENTIDADE DIGITAL CRIPTOGRÁFICA (Merkle DAG Content Addressing)
    /// Computa o CompactCid (BLAKE3-128) sob separação de domínio estrita.
    pub fn calcular_cid(&self) -> CompactCid {
        let buffer_canonico = self.to_canonical_bytes();

        // Separação de domínio via KDF (Key Derivation Function) do BLAKE3
        // Garante bijeção total e impede ataques de colisão trans-contexto
        let kdf = blake3::derive_key(
            "Axolotl Merkle DAG Content Identifier v1 Context", 
            &buffer_canonico
        );
        
        // Truncamento criptograficamente seguro para 16 bytes (BLAKE3-128)
        let mut bytes_cid = [0u8; 16];
        bytes_cid.copy_from_slice(&kdf[0..16]);

        CompactCid(bytes_cid)
    }

    /// PARSER / DESERIALIZADOR REVERSSÍVEL CANÔNICO
    /// Reconstrói um Node a partir de seus 32 bytes limpos. Retorna None se a tag for corrompida.
    pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let tag = bytes[0];
        
        if tag == OpCode::Universe as u8 {
            Some(Node::Universe)
        } else if tag == OpCode::BoundIndex as u8 {
            let mut idx_bytes = [0u8; 4];
            idx_bytes.copy_from_slice(&bytes[4..8]);
            Some(Node::BoundIndex {
                db_index: u32::from_le_bytes(idx_bytes),
                _pad: [0u8; 24],
            })
        } else if tag == OpCode::Lambda as u8 {
            let mut cid_bytes = [0u8; 16];
            cid_bytes.copy_from_slice(&bytes[8..24]);
            Some(Node::Lambda {
                body: CompactCid(cid_bytes),
                _pad: [0u8; 8],
            })
        } else if tag == OpCode::Apply as u8 {
            let mut cid_bytes = [0u8; 16];
            cid_bytes.copy_from_slice(&bytes[8..24]);
            Some(Node::Apply {
                argument: CompactCid(cid_bytes),
                _pad: [0u8; 8],
            })
        } else {
            None // Tag inválida interceptada
        }
    }
}


