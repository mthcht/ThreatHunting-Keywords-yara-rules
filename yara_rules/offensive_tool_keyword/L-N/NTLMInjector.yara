rule NTLMInjector
{
    meta:
        description = "Detection patterns for the tool 'NTLMInjector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMInjector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string1 = /\/NTLMInjector\.git/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string2 = /\/SetNTLM\.ps1/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string3 = /\\SetNTLM\.ps1/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string4 = /197f8806b3b467c66ad64b187f831f10ddd71695d61a42344ae617ee62e62faa/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string5 = /ce4255704740f395be5713b049b97814ce537c440b1249850bcb62794dcc7f56/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string6 = /namespace\sNTLMInjector/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string7 = /NTLMInjector\.ps1/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string8 = /public\sclass\sNTLMInjector/ nocase ascii wide
        // Description: restore the user password after a password reset (get the previous hash with DCSync)
        // Reference: https://github.com/vletoux/NTLMInjector
        $string9 = /vletoux\/NTLMInjector/ nocase ascii wide

    condition:
        any of them
}
