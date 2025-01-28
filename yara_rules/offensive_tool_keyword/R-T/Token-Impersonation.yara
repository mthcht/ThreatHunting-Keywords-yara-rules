rule Token_Impersonation
{
    meta:
        description = "Detection patterns for the tool 'Token-Impersonation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Token-Impersonation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string1 = " -Steal -ProcessID " nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string2 = /\sToken\-Impersonation\.ps1/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string3 = /\$StealToken/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string4 = /\/Token\-Impersonation\.git/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string5 = /\/Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string6 = /\[\+\]\sImpersonation\ssuccessful\susing\stoken\sfrom\sPID\s/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string7 = /\\Token\-Impersonation\.ps1/ nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string8 = "42e10ec6f9a5276060bade151ccd929325daa8ac8910ee26de5e6eebe10f77aa" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string9 = "Leo4j/Token-Impersonation" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string10 = "Token-Impersonation -MakeToken" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string11 = "Token-Impersonation -Rev2Self" nocase ascii wide
        // Description: Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)
        // Reference: https://github.com/Leo4j/Token-Impersonation
        $string12 = "Token-Impersonation -Steal" nocase ascii wide

    condition:
        any of them
}
