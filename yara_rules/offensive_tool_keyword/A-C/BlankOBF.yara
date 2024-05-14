rule BlankOBF
{
    meta:
        description = "Detection patterns for the tool 'BlankOBF' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlankOBF"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string1 = /\sBlankOBFv2\.py/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string2 = /\/BlankOBF\.git/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string3 = /\/BlankOBFv2\.py/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string4 = /\\BlankOBFv2\.py/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string5 = /bc4657ac480d1f46349254c1d217dba4725fe54bbfa5fe7492c6a1bf1c6afebe/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string6 = /Blank\-c\/BlankOBF/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string7 = /BlankOBF\sv2\:\sObfuscates\sPython\scode\sto\smake\sit\sunreadable\sand\shard\sto\sreverse/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string8 = /from\sBlankOBFv2\simport\s/ nocase ascii wide
        // Description: BlankOBF is a Python obfuscation tool designed to make Python programs harder to understand
        // Reference: https://github.com/Blank-c/BlankOBF
        $string9 = /You\smanaged\sto\sbreak\sthrough\sBlankOBF\sv2\;\sGive\syourself\sa\spat\son\syour\sback\!/ nocase ascii wide

    condition:
        any of them
}
