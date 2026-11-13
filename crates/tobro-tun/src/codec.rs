//! Length-delimited JSON codec for the helper protocol.
//!
//! Mirrors `tobro-ipc` framing (4-byte big-endian length + UTF-8 JSON) with
//! its own smaller [`MAX_FRAME_LEN`](crate::MAX_FRAME_LEN) cap.

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

use crate::{HelperError, HelperMessage, MAX_FRAME_LEN};

/// Codec used by both sides of the helper connection.
#[derive(Debug)]
pub struct HelperCodec {
    inner: LengthDelimitedCodec,
}

impl HelperCodec {
    /// Codec with the default 4-byte big-endian length field and the helper
    /// frame cap.
    pub fn new() -> Self {
        let mut inner = LengthDelimitedCodec::new();
        inner.set_max_frame_length(MAX_FRAME_LEN);
        Self { inner }
    }
}

impl Default for HelperCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for HelperCodec {
    type Item = HelperMessage;
    type Error = HelperError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(frame) = self.inner.decode(src)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&frame)?))
    }
}

impl Encoder<HelperMessage> for HelperCodec {
    type Error = HelperError;

    fn encode(&mut self, item: HelperMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let data = serde_json::to_vec(&item)?;
        if data.len() > MAX_FRAME_LEN {
            return Err(HelperError::Protocol(format!(
                "frame is {} bytes, limit is {MAX_FRAME_LEN}",
                data.len()
            )));
        }
        self.inner.encode(bytes::Bytes::from(data), dst)?;
        Ok(())
    }
}
