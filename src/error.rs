use std::error::Error;

#[derive(Debug)]
pub enum NoiseError {
    DecryptionError,
    UnsupportedMessageLengthError,
    ExhaustedNonceError,
    InvalidKeyError,
    InvalidPublicKeyError,
    EmptyKeyError,
    InvalidInputError,
    DerivePublicKeyFromEmptyKeyError,
    Hex(hex::FromHexError),
    MissingnsError,
    MissingneError,
    MissingHsMacError,
    MissingrsError,
    MissingreError
}

impl Error for NoiseError {}

impl std::fmt::Display for NoiseError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            NoiseError::DecryptionError => write!(f, "Unsuccesful decryption; the sender was not authenticated."),
            NoiseError::UnsupportedMessageLengthError => write!(f, "Unsupported Message Length; the length of a transport message must be exclusively between 0 and 0xFFFF bytes."),
            NoiseError::ExhaustedNonceError => write!(f, "Reached maximum number of messages that can be sent for this session. You must end terminate this session and start a new one."),
            NoiseError::DerivePublicKeyFromEmptyKeyError => write!(f, "Unable to derive PublicKey; it is forbidden to derive a PublicKey from an Empty PrivateKey."),
            NoiseError::InvalidKeyError => write!(f, "Invalid Key; the key must be exactly 32 bytes of length."),
            NoiseError::InvalidPublicKeyError => write!(f, "Invalid Public Key; the public key must be derived using a Curve25519 operation."),
            NoiseError::EmptyKeyError => write!(f, "Empty Key."),
            NoiseError::InvalidInputError => write!(f, "Invalid input length; the input string exactly 32 bytes of length."),
            NoiseError::MissingnsError => write!(f, "Invalid message length; you have not allocated enough space for ns in your handshake message."),
            NoiseError::MissingneError => write!(f, "Invalid message length; you have not allocated enough space for ne in your handshake message."),
            NoiseError::MissingrsError => write!(f, "Invalid message length; you have not included rs in your handshake message."),
            NoiseError::MissingreError => write!(f, "Invalid message length; you have not included re in your handshake message."),
            NoiseError::MissingHsMacError => write!(f, "Invalid message length; you have not included the MAC place holder for either the ciphertext or rs in one of your handshake messages."),
            NoiseError::Hex(ref e) => e.fmt(f),
        }
    }
}

impl From<hex::FromHexError> for NoiseError {
    fn from(err: hex::FromHexError) -> NoiseError {
        NoiseError::Hex(err)
    }
}
