rule DPAT
{
    meta:
        description = "Detection patterns for the tool 'DPAT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DPAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string1 = /\/dpat\.py/ nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string2 = /\/ntlmUserPasswords\.ntlm/ nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string3 = /\\dpat\.py/ nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string4 = /_DomainPasswordAuditReport\.html/ nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string5 = "2fe5dc013f99c83e5c353ab5a064ad0ce2f197debb7b03f430934004923f6071" nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string6 = "clr2of8/DPAT" nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string7 = /crack_it\(nt_hash\,\slm_pass\)/ nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string8 = /\-n\sntds\.dit\s\-c\shashcat/ nocase ascii wide
        // Description: Domain Password Audit Tool for Pentesters
        // Reference: https://github.com/clr2of8/DPAT
        $string9 = /users_only_cracked_through_lm\.html/ nocase ascii wide

    condition:
        any of them
}
