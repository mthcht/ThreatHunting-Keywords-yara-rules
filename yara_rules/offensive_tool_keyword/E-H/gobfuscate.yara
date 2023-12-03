rule gobfuscate
{
    meta:
        description = "Detection patterns for the tool 'gobfuscate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gobfuscate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: When you compile a Go binary. it contains a lot of information about your source code: field names. strings. package paths. etc. If you want to ship a binary without leaking this kind of information. what are you to do? With gobfuscate. you can compile a Go binary from obfuscated source code. This makes a lot of information difficult or impossible to decipher from the binary.
        // Reference: https://github.com/unixpickle/gobfuscate
        $string1 = /.{0,1000}gobfuscate.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
