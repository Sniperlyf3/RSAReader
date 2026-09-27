namespace RSAReader;

/// <summary>
/// A secure-messaging session over which files can be selected and read. Implemented
/// by the BAC/3DES (<see cref="SecureMessaging"/>) and PACE/AES
/// (<see cref="AesSecureMessaging"/>) variants so discovery logic can be shared.
/// The Try* methods return the card status word instead of throwing, for probing.
/// </summary>
internal interface ISecureMessaging
{
    Action<string>? Trace { get; set; }
    (int Status, byte[] Data) ReadAt(int offset, int length);
    (int Status, byte[] Fci) TrySelectPath(byte[] path);
    int TrySelectApplication(byte[] aid);
    /// <summary>SELECT a disclosed application requesting its FCI.</summary>
    (int Status, byte[] Fci) TrySelectApplicationWithFci(byte[] aid);
    int TrySelectFile(byte[] fileId);
    /// <summary>SELECT a known EF requesting its FCI. The returned bytes remain local.</summary>
    (int Status, byte[] Fci) TrySelectFileWithFci(byte[] fileId);
    /// <summary>GET DATA for a named two-byte BER tag, without changing card data.</summary>
    (int Status, byte[] Data) TryGetData(byte p1, byte p2);

    /// <summary>READ BINARY addressing a short EF identifier (ISO 7816-4: P1 bit 8 set,
    /// P1 bits 5-1 = SFI, P2 = offset). Read-only; selects the EF as a side effect.</summary>
    (int Status, byte[] Data) ReadShortEf(int sfi, int offset, int length);

    /// <summary>SELECT by DF name (P1=04). <paramref name="next"/> requests the next
    /// matching occurrence (P2=02) instead of the first (P2=00). The name may be a
    /// truncated AID prefix, letting undisclosed applets surface. Returns the FCI.</summary>
    (int Status, byte[] Fci) TrySelectApplicationByName(byte[] name, bool next);
    void SelectApplication(byte[] aid);
    void SelectFile(byte[] fileId);

    /// <summary>Reads a transparent EF whose length is given by its leading TLV header.</summary>
    byte[] ReadFile();

    /// <summary>Reads a transparent EF to end-of-file, for files that are not a single TLV
    /// (e.g. PKCS#15 directory files, which are concatenated records).</summary>
    byte[] ReadEntireFile();

    /// <summary>Reads a transparent EF that may contain opaque non-TLV bytes.</summary>
    byte[] ReadOpaqueFile();

    /// <summary>Returns the status of a read-only one-byte probe on the selected EF.</summary>
    int ProbeReadByteStatus();
}
