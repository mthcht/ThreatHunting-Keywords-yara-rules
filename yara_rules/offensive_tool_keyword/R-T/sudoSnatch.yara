rule sudoSnatch
{
    meta:
        description = "Detection patterns for the tool 'sudoSnatch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudoSnatch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: sudoSnatch payload grabs sudo password in plain text and imediately after target uses sudo command and sends it back to attacker remotely/locally.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SudoSnatch
        $string1 = /\/credentials\/SudoSnatch/ nocase ascii wide
        // Description: sudoSnatch payload grabs sudo password in plain text and imediately after target uses sudo command and sends it back to attacker remotely/locally.
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/SudoSnatch
        $string2 = /nIFS\=.{0,1000}\sread\s\-s\spass\\necho\s\-e\s.{0,1000}User\=.{0,1000}\$\(whoami\).{0,1000}Password\=.{0,1000}\$pass.{0,1000}\>\s\/var\/tmp/ nocase ascii wide

    condition:
        any of them
}
