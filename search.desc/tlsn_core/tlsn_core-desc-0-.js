searchState.loadedDescShard("tlsn_core", 0, "TLSNotary core library.\nCryptography provider.\nSecret data of an <code>Attestation</code>.\nAttestation types.\nCertificate verifier.\nTLS connection types.\nFixtures for testing\nReturns the argument unchanged.\nReturns the argument unchanged.\nHash types.\nHash provider.\nReturns a server identity proof.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nVerifiable presentation.\nAttestation requests.\nReturns the server name.\nSignature verifier provider.\nSigner provider.\nCryptographic signatures.\nTranscript types.\nReturns the transcript.\nReturns a transcript proof builder.\nAn attestation document.\nAn attestation builder.\nError for <code>AttestationBuilder</code>.\nAttestation configuration.\nBuilder for <code>AttestationConfig</code>.\nError for <code>AttestationConfig</code>.\nError for <code>AttestationProof</code>.\nProof of an attestation.\nAttestation body.\nConnection information.\nEncoding commitment.\nAn attestation extension.\nPublic attestation field.\nIdentifier for a field.\nKind of an attestation field.\nAttestation header.\nInvalid extension error.\nPlaintext hash commitment.\nServer ephemeral key.\nServer identity commitment.\nUnique identifier for an attestation.\nCurrent version of attestations.\nVersion of an attestation.\nAccepts the attestation request.\nThe attestation body.\nBuilds the configuration.\nBuilds the attestation.\nCreates a new builder.\nReturns an attestation builder.\nSets the connection information.\nField data.\nSets the encoder secret.\nAdds an extension to the attestation.\nSets the extension validator.\nReturns an iterator over the extensions.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nThe attestation header.\nExtension identifier.\nIdentifier of the field.\nAn identifier for the attestation.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns whether the error originates from a bad request.\nCreates a new attestation builder.\nCreates a new invalid extension error.\nReturns a presentation builder.\nMerkle root of the attestation fields.\nSets the server ephemeral key.\nThe signature of the attestation.\nSets the supported attestation fields.\nSets the supported hash algorithms.\nSets the supported signature algorithms.\nExtension data.\nVerifies the attestation proof.\nReturns the verifying key.\nReturns the attestation verifying key.\nVersion of the attestation.\nX.509 certificate, DER encoded.\nErrors that can occur when verifying a certificate chain …\nTLS session information.\nTLS handshake data.\nTLS 1.2 handshake data.\nType of a public key.\nsecp256r1.\nCommitment to a server certificate.\nServer certificate and handshake data.\nOpens a <code>ServerCertCommitment</code>.\nServer’s ephemeral public key.\nTLS server identity proof.\nError for <code>ServerIdentityProof</code>.\nServer’s name, a.k.a. the DNS name.\nServer’s signature of the key exchange parameters.\nSignature scheme on the key exchange parameters.\nTLS version.\nTranscript length information.\nTLS 1.2.\nTLS 1.2 handshake data.\nTLS 1.3.\nReturns the name as a string.\nCertificate chain.\nClient random.\nReturns the server identity data.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nTLS handshake data.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nPublic key data.\nCreates a new server name.\nNumber of bytes received by the Prover from the Server.\nSignature scheme.\nNumber of bytes sent by the Prover to the Server.\nServer’s ephemeral public key.\nServer random.\nSignature data.\nServer signature of the key exchange parameters.\nUNIX time when the TLS connection started.\nTranscript length.\nType of the public key.\nVerifies the server identity proof.\nVerifies the server certificate data.\nTLS version used in the connection.\nA fixture containing various TLS connection data.\nA encoding provider fixture.\nA Request fixture used for testing.\nReturns a connection fixture for appliedzkp.org.\nReturns an attestation fixture for testing.\nReturns an encoder secret fixture.\nReturns a tampered encoder secret fixture.\nReturns an encoding provider fixture.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns a notary signing key fixture.\nReturns a request fixture for testing.\nReturns the server_ephemeral_key fixture.\nReturns a connection fixture for tlsnotary.org.\nBLAKE3 hash algorithm.\nBLAKE3 hash algorithm.\nA hash value.\nA hash algorithm identifier.\nA hashing algorithm.\nHash provider.\nAn error for <code>HashProvider</code>.\nKeccak-256 hash algorithm.\nKeccak-256 hash algorithm.\nSHA-256 hash algorithm.\nSHA-256 hash algorithm.\nA typed hash value.\nThe algorithm of the hash.\nReturns the id as a <code>u8</code>.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the hash algorithm with the given identifier, or …\nComputes the hash of the provided data.\nComputes the hash of the provided data with a prefix.\nReturns the hash algorithm identifier.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new hash algorithm identifier.\nSets a hash algorithm.\nThe hash value.\nA verifiable presentation.\nBuilder for <code>Presentation</code>.\nError for <code>PresentationBuilder</code>.\nError for <code>Presentation</code>.\nOutput of a verified <code>Presentation</code>.\nVerified attestation.\nBuilds the presentation.\nCreates a new builder.\nConnection information.\nExtensions.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nIncludes a server identity proof.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAuthenticated server name.\nAuthenticated transcript data.\nIncludes a transcript proof.\nVerifies the presentation.\nReturns the verifying key.\nError for <code>Request::validate</code>.\nAttestation request.\nBuilder for <code>Request</code>.\nError for <code>RequestBuilder</code>.\nRequest configuration.\nBuilder for <code>RequestConfig</code>.\nError for <code>RequestConfigBuilder</code>.\nBuilds the attestation request and returns the …\nBuilds the config.\nCreates a new builder.\nReturns a new request builder.\nSets the tree to commit to the transcript encodings.\nAdds an extension to the request.\nAdds an extension to the request.\nReturns the extensions.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the hash algorithm.\nSets the hash algorithm.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new request builder.\nSets the server identity data.\nSets the server name.\nReturns the signature algorithm.\nSets the signature algorithm.\nSets the transcript.\nValidates the content of the attestation against this …\nsecp256k1 elliptic curve key algorithm.\nKey algorithm identifier.\nNIST P-256 elliptic curve key algorithm.\nsecp256k1 signature algorithm with SHA-256 hashing.\nEthereum-compatible signature algorithm.\nsecp256r1 signature algorithm with SHA-256 hashing.\nsecp256k1eth signer.\nsecp256k1eth verifier.\nsecp256k1 signer with SHA-256 hashing.\nsecp256k1 verifier with SHA-256 hashing.\nsecp256r1 signer with SHA-256 hashing.\nsecp256r1 verifier with SHA-256 hashing.\nA signature.\nSignature algorithm identifier.\nError that can occur while verifying a signature.\nSignature verifier.\nProvider of signature verifiers.\nCryptographic signer.\nError for <code>Signer</code>.\nProvider of signers.\nUnknown signature algorithm error.\nVerifying key.\nThe key algorithm.\nThe algorithm used to sign the data.\nReturns the algorithm used by this signer.\nReturns the algorithm used by this verifier.\nReturns the id as a <code>u8</code>.\nReturns the id as a <code>u8</code>.\nThe key data.\nThe signature data.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCreates a new secp256k1 signer with the provided signing …\nCreates a new secp256r1 signer with the provided signing …\nCreates a new secp256k1eth signer with the provided …\nCreates a new key algorithm identifier.\nCreates a new signature algorithm identifier.\nConfigures a secp256k1 signer with the provided signing …\nConfigures a secp256k1eth signer with the provided signing …\nConfigures a secp256r1 signer with the provided signing …\nConfigures a signer.\nConfigures a signature verifier.\nSigns the message.\nReturns the supported signature algorithms.\nVerifies the signature.\nReturns the verifying key for this signer.\n<code>PartialTranscript</code> in a compressed form.\nThe direction of data communicated over a TLS connection.\nA commitment to encodings of the transcript.\nA hash commitment to plaintext in the transcript.\nTranscript index.\nBuilder for <code>Idx</code>.\nInvalid subsequence error.\nA partial transcript.\nReceived by the prover from the TLS peer.\nSent from the Prover to the TLS peer.\nTranscript subsequence.\nA transcript contains the plaintext of all application …\nConfiguration for transcript commitments.\nA builder for <code>TranscriptCommitConfig</code>.\nError for <code>TranscriptCommitConfigBuilder</code>.\nKind of transcript commitment.\nProof of the contents of a transcript.\nBuilder for <code>TranscriptProof</code>.\nError for <code>TranscriptProofBuilder</code>.\nError for <code>TranscriptProof</code>.\nBuilds the configuration.\nBuilds the transcript proof.\nBuilds the index.\nCreates a new commit config builder.\nCreates a new index builder.\nAdds a commitment with the default kind.\nAdds a commitment with the default kind to the received …\nAdds a commitment with the default kind to the sent data …\nAdds a commitment.\nSets the commitment kinds in order of preference for …\nReturns whether the index is in bounds of the transcript.\nReturns the number of disjoint ranges in the index.\nReturns the data of the subsequence.\nSets the default kind of commitment to use.\nCreates an empty index.\nReturns the hash algorithm to use for encoding commitments.\nSets the hash algorithm to use for encoding commitments.\nReturns the end of the index, non-inclusive.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the subsequence of the transcript with the …\nReturns whether the configuration has any encoding …\nReturns the index of the subsequence.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the inner parts of the subsequence.\nReturns whether the transcript is complete.\nReturns whether the index is empty.\nReturns an iterator over the authenticated data in the …\nReturns an iterator over the values in the index.\nReturns an iterator over the encoding commitment indices.\nReturns an iterator over the hash commitment indices.\nReturns an iterator over the ranges of the index.\nReturns the length of the sent and received data, …\nReturns the number of values in the index.\nReturns the length of the subsequence.\nReturns the length of the received transcript.\nReturns the length of the sent transcript.\nReturns the transcript length.\nCreates a new commit config builder.\nCreates a new transcript.\nCreates a new partial transcript initalized to all 0s.\nCreates a new transcript index.\nCreates a new subsequence.\nReturns a reference to the received data.\nReturns the index of received data which have been …\nReturns the index of received data which haven’t been …\nReturns a reference to the received data.\nReveals the given ranges in the transcript.\nReveals the given ranges in the received transcript.\nReveals the given ranges in the sent transcript.\nReturns a reference to the sent data.\nReturns the index of sent data which have been …\nReturns the index of sent data which haven’t been …\nReturns a reference to the sent data.\nSets all bytes in the transcript which haven’t been …\nSets all bytes in the transcript which haven’t been …\nReturns the start of the index.\nReturns a partial transcript containing the provided …\nUnions ranges.\nUnions an authenticated subsequence into this transcript.\nUnions the authenticated data of this transcript with …\nVerifies the proof.\nThe hash algorithm used.")