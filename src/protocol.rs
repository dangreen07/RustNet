use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, io};
use libp2p::request_response::Codec;
use serde::{Deserialize, Serialize};

pub const PROTO_ID: &str = "rustnet/blocks/1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageKind {
    /// Ask a peer for its best block height and the corresponding tip hash.
    RequestTip,

    RespondTip {
        best_height: u64,
        tip_hash: [u8; 32],
    },

    RequestBlocks {
        from_height: u64,
        to_height: u64,
    },

    RespondBlocks {
        blocks: Vec<Vec<u8>>, // Raw encoded blocks
    },

    RequestBalance {
        /// Compressed SEC1 public key (33 bytes).  The vector **must** be 33
        /// bytes long; peers should reject requests with invalid lengths.
        public_key: Vec<u8>,
    },

    RespondBalance {
        balance: f64,
    },
    // ---------------------------------------------------------------------
    // New message types should be added **below** this comment so that
    // existing numeric discriminants remain stable.  Never rearrange the order
    // of variants; doing so would be a wire-format breaking change.
    // ---------------------------------------------------------------------
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Protocol version understood by both peers.  Nodes **must** ignore
    /// messages with a higher version number that they do not understand.
    pub version: String,

    /// Concrete request / response being transmitted.
    pub kind: MessageKind,
}

impl ProtocolMessage {
    #[inline]
    pub fn new(kind: MessageKind) -> Self {
        Self {
            version: PROTO_ID.to_string(),
            kind,
        }
    }

    /// Serialise the message to bytes using `serde_json` (human-readable, easy
    /// to debug).  Switch to a more compact encoding (e.g. `bincode`) once the
    /// protocol is stable.
    #[inline]
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialise ProtocolMessage")
    }

    /// Attempt to deserialise a [`ProtocolMessage`] from the provided byte
    /// buffer.
    #[inline]
    pub fn decode(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

#[derive(Clone, Default)]
pub struct ProtoCodec;

impl Codec for ProtoCodec {
    /// The type of protocol(s) or protocol versions being negotiated.
    type Protocol = String;
    /// The type of inbound and outbound requests.
    type Request = ProtocolMessage;

    /// The type of inbound and outbound responses.
    type Response = ProtocolMessage;

    /// Reads a request from the given I/O stream according to the
    /// negotiated protocol.
    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = io::Result<Self::Request>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        T: AsyncRead + Unpin + Send,
        T: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            // Read 4-byte big-endian length prefix indicating payload size.
            let mut len_buf = [0u8; 4];
            io.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;

            // Allocate a buffer of the declared size and fill it completely.
            let mut buf = vec![0u8; len];
            io.read_exact(&mut buf).await?;

            // Attempt to decode the JSON payload into a `ProtocolMessage`.
            ProtocolMessage::decode(&buf)
                .map_err(|e| futures::io::Error::new(futures::io::ErrorKind::InvalidData, e))
        })
    }

    /// Reads a response from the given I/O stream according to the
    /// negotiated protocol.
    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = io::Result<Self::Response>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        T: AsyncRead + Unpin + Send,
        T: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.read_request(protocol, io)
    }

    /// Writes a request to the given I/O stream according to the
    /// negotiated protocol.
    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = io::Result<()>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        T: AsyncWrite + Unpin + Send,
        T: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let data = req.encode();
            let length = data.len() as u32;
            let length: [u8; 4] = length.to_be_bytes();
            io.write_all(&length).await?;
            io.write_all(&data).await
        })
    }

    /// Writes a response to the given I/O stream according to the
    /// negotiated protocol.
    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        res: Self::Response,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = io::Result<()>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        T: AsyncWrite + Unpin + Send,
        T: 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        self.write_request(protocol, io, res)
    }
}
