namespace RSAReader;

/// <summary>
/// A secure-messaging session over which files can be selected and read. Implemented
/// by the BAC/3DES (<see cref="SecureMessaging"/>) and PACE/AES
/// (<see cref="AesSecureMessaging"/>) variants so discovery logic can be shared.
/// The Try* methods return the card status word instead of throwing, for probing.
/// </summary>
internal interface ISecureMessaging
{
    int TrySelectApplication(byte[] aid);
    int TrySelectFile(byte[] fileId);
    void SelectApplication(byte[] aid);
    void SelectFile(byte[] fileId);

    /// <summary>Reads a transparent EF whose length is given by its leading TLV header.</summary>
    byte[] ReadFile();

    /// <summary>Reads a transparent EF to end-of-file, for files that are not a single TLV
    /// (e.g. PKCS#15 directory files, which are concatenated records).</summary>
    byte[] ReadEntireFile();

    /// <summary>Reads a transparent EF that may contain opaque non-TLV bytes.</summary>
    byte[] ReadOpaqueFile();
}
