rule Encfile_Ransom_Note_Indicators
{
    meta:
        description = "Low-confidence phrases observed in the encfile ransom note"
        author = "encfile-public-analysis contributors"
        date = "2026-10-26"
        sample_sha256 = "a8bfba3c98cc0bf2c6af42e1d17e8d34f5a010509c93fe95daf518a663e2112d"
        confidence = "medium; generic phrases, validate context"

    strings:
        $a = "YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase
        $b = "Password Needed for Decryption" ascii wide nocase
        $c = "Do NOT attempt to use third-party recovery tools" ascii wide nocase

    condition:
        filesize < 1MB and 2 of them
}
