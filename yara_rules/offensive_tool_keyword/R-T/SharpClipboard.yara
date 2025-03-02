rule SharpClipboard
{
    meta:
        description = "Detection patterns for the tool 'SharpClipboard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpClipboard"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string1 = /\/SharpClipboard\.git/ nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string2 = /\\SharpClipboard\.csproj/ nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string3 = /\\SharpClipboard\.sln/ nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string4 = /\\SharpClipboard\\/ nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string5 = ">SharpClipboard<" nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string6 = "0556d3a1e4719382613891895582f8a392ccacfab6814bc9deafa9c99c86e553" nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string7 = "1ff4136cc59aec4f76d776abce00a592679490763f669a44eeead8f88c4a3c07" nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string8 = "803c76c8edc3cb686137d642d75fcedd54b89461c719504f2e5f8a3235c3f7c3" nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string9 = "97484211-4726-4129-86AA-AE01D17690BE" nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string10 = "981d1e5d88087f716ebb0cf8b39ffe7d3e44c36bc1e34452c8eaf2eaa56c05f9" nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string11 = /SharpClipboard\.exe/ nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string12 = /SharpClipboard\-master\.zip/ nocase ascii wide
        // Description: monitor the content of the clipboard continuously
        // Reference: http://github.com/slyd0g/SharpClipboard
        $string13 = "slyd0g/SharpClipboard" nocase ascii wide

    condition:
        any of them
}
