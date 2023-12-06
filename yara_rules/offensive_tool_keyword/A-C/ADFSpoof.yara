rule ADFSpoof
{
    meta:
        description = "Detection patterns for the tool 'ADFSpoof' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string1 = /\sADFSpoof\.py/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string2 = /\s\-b\s.{0,1000}\.bin\s.{0,1000}\.bin\sdump/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string3 = /\/ADFSpoof\.py/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string4 = /\\ADFSpoof\.py/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string5 = /ADFSpoof\-master/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string6 = /EncryptedPfx\.py/ nocase ascii wide

    condition:
        any of them
}
