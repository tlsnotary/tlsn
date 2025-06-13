function isNull(v: any): boolean {
  return v === undefined || v === null;
}

function cast(caster: (v: any) => any, v: any): any {
  if (isNull(v)) return v;
  return caster(v);
}

function castArray(caster: (v: any) => any) {
  return (v?: Array<any>) => {
    if (isNull(v)) return v;
    caster = cast.bind(null, caster); // bind to null-preserving logic in `cast`
    return v!.map(caster);
  };
}

function castMap(caster: (v: any) => any) {
  return (v?: any) => {
    if (isNull(v)) return v;

    caster = cast.bind(null, caster); // bind to null-preserving logic in `cast`
    const newMap: any = {};
    for (const k in v) {
      newMap[k] = caster(v![k]);
    }
    return newMap;
  };
}

function dateToJson(v?: Date): string | undefined | null {
  if (v === undefined || v === null) return v;
  return v.toISOString();
}
function dateFromJson(v?: string): Date | undefined | null {
  if (v === undefined || v === null) return v;
  return new Date(v);
}

function bufferToJson(v?: ArrayBuffer): string | undefined | null {
  if (v === undefined || v === null) return v;
  return Host.arrayBufferToBase64(v);
}
function bufferFromJson(v?: string): ArrayBuffer | undefined | null {
  if (v === undefined || v === null) return v;
  return Host.base64ToArrayBuffer(v);
}

/**
 * Direction of the plaintext
 */
export enum Direction {
  Sent = "Sent",
  Received = "Received",
}

/**
 * Secret used to generate the encodings
 */
export class EncoderSecret {
  /**
   * Delta used to generate the encodings
   */
  // @ts-expect-error TS2564
  delta: Array<number>;

  /**
   * Seed used to generate the encodings
   */
  // @ts-expect-error TS2564
  seed: Array<number>;

  static fromJson(obj: any): EncoderSecret {
    return {
      ...obj,
    };
  }

  static toJson(obj: EncoderSecret): any {
    return {
      ...obj,
    };
  }
}

/**
 * Commitment to the encoding of the transcript data
 */
export class EncodingCommitment {
  /**
   * Merkle root of the encoding commitments
   */
  // @ts-expect-error TS2564
  root: TypedHash;

  /**
   * Secret used to generate the encodings
   */
  // @ts-expect-error TS2564
  secret: EncoderSecret;

  static fromJson(obj: any): EncodingCommitment {
    return {
      ...obj,
      root: cast(TypedHash.fromJson, obj.root),
      secret: cast(EncoderSecret.fromJson, obj.secret),
    };
  }

  static toJson(obj: EncodingCommitment): any {
    return {
      ...obj,
      root: cast(TypedHash.toJson, obj.root),
      secret: cast(EncoderSecret.toJson, obj.secret),
    };
  }
}

/**
 * A partial transcript containing authenticated application data
 */
export class PartialTranscript {
  /**
   * Data received by the prover from the server (byte array)
   */
  // @ts-expect-error TS2564
  received: Array<number>;

  /**
   * Index ranges of authenticated received data
   */
  // @ts-expect-error TS2564
  recvAuthedIdx: Array<Range>;

  /**
   * Data sent from the prover to the server (byte array)
   */
  // @ts-expect-error TS2564
  sent: Array<number>;

  /**
   * Index ranges of authenticated sent data
   */
  // @ts-expect-error TS2564
  sentAuthedIdx: Array<Range>;

  static fromJson(obj: any): PartialTranscript {
    return {
      ...obj,
      recvAuthedIdx: cast(castArray(Range.fromJson), obj.recvAuthedIdx),
      sentAuthedIdx: cast(castArray(Range.fromJson), obj.sentAuthedIdx),
    };
  }

  static toJson(obj: PartialTranscript): any {
    return {
      ...obj,
      recvAuthedIdx: cast(castArray(Range.toJson), obj.recvAuthedIdx),
      sentAuthedIdx: cast(castArray(Range.toJson), obj.sentAuthedIdx),
    };
  }
}

/**
 * Hash of plaintext in the transcript
 */
export class PlaintextHash {
  /**
   * Direction of the plaintext
   */
  // @ts-expect-error TS2564
  direction: Direction;

  /**
   * The hash of the data
   */
  // @ts-expect-error TS2564
  hash: TypedHash;

  /**
   * Indexes of the plaintext in the transcript
   */
  // @ts-expect-error TS2564
  idx: Array<Range>;

  static fromJson(obj: any): PlaintextHash {
    return {
      ...obj,
      hash: cast(TypedHash.fromJson, obj.hash),
      idx: cast(castArray(Range.fromJson), obj.idx),
    };
  }

  static toJson(obj: PlaintextHash): any {
    return {
      ...obj,
      hash: cast(TypedHash.toJson, obj.hash),
      idx: cast(castArray(Range.toJson), obj.idx),
    };
  }
}

/**
 * The verifier configuration.
 */
export class PluginVerifierConfig {
  /**
   * Maximum data that can be received by the prover in bytes
   */
  maxRecvData?: number | null;

  /**
   * Maximum number of application data records that can be received online
   */
  maxRecvRecordsOnline?: number | null;

  /**
   * Maximum data that can be sent by the prover in bytes
   */
  maxSentData?: number | null;

  /**
   * Maximum number of application data records that can be sent
   */
  maxSentRecords?: number | null;

  static fromJson(obj: any): PluginVerifierConfig {
    return {
      ...obj,
    };
  }

  static toJson(obj: PluginVerifierConfig): any {
    return {
      ...obj,
    };
  }
}

/**
 * A range with start (inclusive) and end (exclusive) positions
 */
export class Range {
  /**
   * End position (exclusive)
   */
  // @ts-expect-error TS2564
  end: number;

  /**
   * Start position (inclusive)
   */
  // @ts-expect-error TS2564
  start: number;

  static fromJson(obj: any): Range {
    return {
      ...obj,
    };
  }

  static toJson(obj: Range): any {
    return {
      ...obj,
    };
  }
}

/**
 * Cryptographic commitment to transcript data
 */
export class TranscriptCommitment {
  /**
   * Commitment to the encoding of the transcript data
   */
  encodingCommitment?: EncodingCommitment;

  /**
   * Hash of plaintext in the transcript
   */
  plaintextHash?: PlaintextHash;

  static fromJson(obj: any): TranscriptCommitment {
    return {
      ...obj,
      encodingCommitment: cast(
        EncodingCommitment.fromJson,
        obj.encodingCommitment,
      ),
      plaintextHash: cast(PlaintextHash.fromJson, obj.plaintextHash),
    };
  }

  static toJson(obj: TranscriptCommitment): any {
    return {
      ...obj,
      encodingCommitment: cast(
        EncodingCommitment.toJson,
        obj.encodingCommitment,
      ),
      plaintextHash: cast(PlaintextHash.toJson, obj.plaintextHash),
    };
  }
}

/**
 * Typed hash with algorithm ID and value
 */
export class TypedHash {
  /**
   * The algorithm ID of the hash
   */
  // @ts-expect-error TS2564
  alg: number;

  /**
   * The hash value in bytes
   */
  // @ts-expect-error TS2564
  value: Array<number>;

  static fromJson(obj: any): TypedHash {
    return {
      ...obj,
    };
  }

  static toJson(obj: TypedHash): any {
    return {
      ...obj,
    };
  }
}

/**
 * Output from the MPC-TLS verification containing verified session data
 */
export class VerifierOutput {
  /**
   * The server's DNS name if revealed by the prover
   */
  serverName?: string | null;

  /**
   * The partial transcript containing authenticated application data
   */
  transcript?: PartialTranscript;

  /**
   * Cryptographic commitments to transcript data
   */
  // @ts-expect-error TS2564
  transcriptCommitments: Array<TranscriptCommitment>;

  static fromJson(obj: any): VerifierOutput {
    return {
      ...obj,
      transcript: cast(PartialTranscript.fromJson, obj.transcript),
      transcriptCommitments: cast(
        castArray(TranscriptCommitment.fromJson),
        obj.transcriptCommitments,
      ),
    };
  }

  static toJson(obj: VerifierOutput): any {
    return {
      ...obj,
      transcript: cast(PartialTranscript.toJson, obj.transcript),
      transcriptCommitments: cast(
        castArray(TranscriptCommitment.toJson),
        obj.transcriptCommitments,
      ),
    };
  }
}
