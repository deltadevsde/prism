use pkcs8::{
    der::{
        self, AnyRef, DecodeValue, Encode, EncodeValue, Header, Length, Reader, Sequence, Writer,
        asn1::{ContextSpecific, OctetStringRef},
    },
    spki::AlgorithmIdentifier,
};

pub struct SignatureInfoRef<'a> {
    pub algorithm: AlgorithmIdentifier<AnyRef<'a>>,
    pub signature: OctetStringRef<'a>,
}

impl<'a> SignatureInfoRef<'a> {}

impl<'a> EncodeValue for SignatureInfoRef<'a> {
    fn value_len(&self) -> der::Result<Length> {
        self.algorithm.encoded_len()? + self.signature.encoded_len()?
    }

    fn encode_value(&self, encoder: &mut impl Writer) -> der::Result<()> {
        self.algorithm.encode(encoder)?;
        self.signature.encode(encoder)?;
        Ok(())
    }
}

impl<'a> DecodeValue<'a> for SignatureInfoRef<'a> {
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length, |reader| {
            let algorithm = reader.decode()?;
            let signature = reader.decode()?;

            // Ignore any remaining extension fields
            while !reader.is_finished() {
                reader.decode::<ContextSpecific<AnyRef<'_>>>()?;
            }

            Ok(Self {
                algorithm,
                signature,
            })
        })
    }
}

impl<'a> Sequence<'a> for SignatureInfoRef<'a> {}
