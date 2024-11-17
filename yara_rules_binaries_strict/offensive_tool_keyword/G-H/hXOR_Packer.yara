rule hXOR_Packer
{
    meta:
        description = "Detection patterns for the tool 'hXOR-Packer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hXOR-Packer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string1 = /\/hXOR\.exe/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string2 = /\/hXOR\-Packer\.git/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string3 = /\\antiDefense\.cpp/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string4 = /\\hXOR\.exe/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string5 = /\\hXOR\-Packer\sv0\.1\\/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string6 = /\\hXOR\-Packer\\/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string7 = /\\unpackerLoadEXE\.exe/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string8 = /akuafif\/hXOR\-Packer/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string9 = /hXOR\-Packer\.v0\.1\.zip/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string10 = /hXOR\-Packer\-main/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string11 = /packer\.exe\s.{0,100}\.exe\s.{0,100}\.exe/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string12 = /Sandboxie\sdetected\!\!\!/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string13 = /Scanning\sfor\sSandboxie\?/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string14 = /Unpacking\sSuccessful\!\\n\\nExecuting\sfrom\sMemory\s\>\>\>\>\s/ nocase ascii wide
        // Description: hXOR Packer is a PE (Portable Executable) packer with Huffman Compression and Xor encryption.
        // Reference: https://github.com/akuafif/hXOR-Packer
        $string15 = /VMware\sdetected\!\!\!/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
