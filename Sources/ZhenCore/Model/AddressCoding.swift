// AddressCoding.swift — the wire form of the packed address types.
//
// The packed representations in Addresses.swift are right for memory and wrong for
// JSON: a MAC as `158829627348993` is unreadable, undiffable, and impossible to grep
// out of a report. Each address encodes as the canonical text form instead, as a
// single JSON scalar rather than an object.
//
// Decoding goes back through the same parsers the rest of the system uses, so a
// hand-edited report with "0:92:35:30:a:1" in it decodes to exactly the value a scan
// would have produced. Malformed text throws a DecodingError with the offending
// string in the message; silently substituting a zero address would put a plausible
// wrong device in the report.

extension MACAddress: Codable {
    /// Decodes from the wire form described above.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let parsed = MACAddress(text) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "'\(text)' is not a MAC address"
            )
        }
        self = parsed
    }

    /// Encodes to the wire form described above.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension IPv4Address: Codable {
    /// Decodes from the wire form described above.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let parsed = IPv4Address(text) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "'\(text)' is not an IPv4 address"
            )
        }
        self = parsed
    }

    /// Encodes to the wire form described above.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

extension IPv4Network: Codable {
    /// Decodes from the wire form described above.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let parsed = IPv4Network(text) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "'\(text)' is not a CIDR network"
            )
        }
        self = parsed
    }

    /// Encodes to the wire form described above.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
