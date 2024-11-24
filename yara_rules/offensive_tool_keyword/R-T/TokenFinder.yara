rule TokenFinder
{
    meta:
        description = "Detection patterns for the tool 'TokenFinder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenFinder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string1 = /\sTokenFinder\.py/ nocase ascii wide
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string2 = /\/TokenFinder\.git/ nocase ascii wide
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string3 = /\/TokenFinder\.py/ nocase ascii wide
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string4 = /\\TokenFinder\.py/ nocase ascii wide
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string5 = "doredry/TokenFinder" nocase ascii wide
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string6 = "f049f7c98172f7696d6a0b312c91010720970f825eb4cff5c76c151e15f16951" nocase ascii wide
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string7 = "python3 TokenFinder" nocase ascii wide
        // Description: Tool to extract powerful tokens from Office desktop apps memory
        // Reference: https://github.com/doredry/TokenFinder
        $string8 = /Tokens\swere\sextracted\sto\stokens\.txt\!\sEnjoy/ nocase ascii wide

    condition:
        any of them
}
