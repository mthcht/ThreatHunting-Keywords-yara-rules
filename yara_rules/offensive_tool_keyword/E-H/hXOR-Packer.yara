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
        $string11 = /packer\.exe\s.{0,1000}\.exe\s.{0,1000}\.exe/ nocase ascii wide
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

    condition:
        any of them
}
