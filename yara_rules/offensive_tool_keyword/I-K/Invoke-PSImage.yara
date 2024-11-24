rule Invoke_PSImage
{
    meta:
        description = "Detection patterns for the tool 'Invoke-PSImage' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-PSImage"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Encodes a PowerShell script in the pixels of a PNG file and generates a oneliner to executenInvoke-PSImage takes a PowerShell script and encodes the bytes of the script into the pixels of a PNG image. It generates a oneliner for executing either from a file of from the web.
        // Reference: https://github.com/peewpw/Invoke-PSImage
        $string1 = "b4c75048a8837dbad2a829e17a1370716cc40f9a6fd3b0f50df7f0e3f97564c1" nocase ascii wide
        // Description: Encodes a PowerShell script in the pixels of a PNG file and generates a oneliner to executenInvoke-PSImage takes a PowerShell script and encodes the bytes of the script into the pixels of a PNG image. It generates a oneliner for executing either from a file of from the web.
        // Reference: https://github.com/peewpw/Invoke-PSImage
        $string2 = /foreach\(\`\$x\sin\(0\.\.\$lwidth\)\)\{\`\$p\=\`\$g\.GetPixel\(\`\$x\,\`\$_\)/ nocase ascii wide
        // Description: Encodes a PowerShell script in the pixels of a PNG file and generates a oneliner to executenInvoke-PSImage takes a PowerShell script and encodes the bytes of the script into the pixels of a PNG image. It generates a oneliner for executing either from a file of from the web.
        // Reference: https://github.com/peewpw/Invoke-PSImage
        $string3 = "Invoke-PSImage" nocase ascii wide

    condition:
        any of them
}
