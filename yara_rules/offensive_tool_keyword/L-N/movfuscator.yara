rule movfuscator
{
    meta:
        description = "Detection patterns for the tool 'movfuscator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "movfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The M/o/Vfuscator (short 'o. sounds like mobfuscator) compiles programs into mov instructions. and only mov instructions. Arithmetic. comparisons. jumps. function calls. and everything else a program needs are all performed through mov operations. there is no self-modifying code. no transport-triggered calculation. and no other form of non-mov cheating
        // Reference: https://github.com/xoreaxeaxeax/movfuscator
        $string1 = /movfuscator/ nocase ascii wide

    condition:
        any of them
}
