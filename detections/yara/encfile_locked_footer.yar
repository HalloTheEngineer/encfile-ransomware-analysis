rule Encfile_Locked_Footer
{
    meta:
        description = "Structural ENCH/ENCF footer used by the observed encfile ransomware build"
        author = "encfile-public-analysis contributors"
        date = "2026-10-26"
        sample_sha256 = "a8bfba3c98cc0bf2c6af42e1d17e8d34f5a010509c93fe95daf518a663e2112d"
        confidence = "structural match; not proof of origin or integrity"

    strings:
        $ench = "ENCH"
        $encf = "ENCF"

    condition:
        filesize >= 0x67 and
        $encf at filesize - 4 and
        (
            (
                filesize >= 0x67 and
                $ench at filesize - 0x67 and
                uint32(filesize - 8) == 0x67 and
                uint8(filesize - 0x67 + 4) == 1 and
                uint8(filesize - 0x67 + 5) == 0 and
                uint8(filesize - 0x67 + 30) == 1
            )
            or
            (
                filesize >= 0xE7 and
                $ench at filesize - 0xE7 and
                uint32(filesize - 8) == 0xE7 and
                uint8(filesize - 0xE7 + 4) == 1 and
                uint8(filesize - 0xE7 + 5) == 1 and
                uint8(filesize - 0xE7 + 30) == 5
            )
        )
}
