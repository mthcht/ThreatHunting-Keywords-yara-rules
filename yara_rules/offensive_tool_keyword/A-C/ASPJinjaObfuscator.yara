rule ASPJinjaObfuscator
{
    meta:
        description = "Detection patterns for the tool 'ASPJinjaObfuscator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ASPJinjaObfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string1 = /\#\sAdd\srandom\snewlines\sto\sthe\sobfuscated\scode/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string2 = /\/ASPJinjaObfuscator\.git/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string3 = /\\ASPJinjaObfuscator/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string4 = /09855e8685bbec09962affefbfad2c554d434a87aca1e1ac8c961f5ebfe6cdad/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string5 = /add_random_newlines\(obfuscated_code/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string6 = /asp\-jinja\-obfuscator\.py/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string7 = /encode_base64\(xor_encrypt\(\"cmd\s\/c\s/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string8 = /encode_base64\(xor_encrypt\(\"WScript\.Shell\"/ nocase ascii wide
        // Description: Heavily obfuscated ASP web shell generation tool.
        // Reference: https://github.com/fin3ss3g0d/ASPJinjaObfuscator
        $string9 = /fin3ss3g0d\/ASPJinjaObfuscator/ nocase ascii wide

    condition:
        any of them
}
