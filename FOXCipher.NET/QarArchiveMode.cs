namespace FOXCipher.NET
{
    public enum QarArchiveMode
    {
        /// <summary>
        /// Only reading archive entries is permitted.
        /// </summary>
        Read,

        /// <summary>
        /// Only creating new archive entries is permitted.
        /// </summary>
        Create,

        /// <summary>
        /// Both read and write operations are permitted for archive entries.
        /// </summary>
        Update,
    }
}
