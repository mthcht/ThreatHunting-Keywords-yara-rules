rule ADCSPwn
{
    meta:
        description = "Detection patterns for the tool 'ADCSPwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSPwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string1 = /\.exe\s\-\-adcs\s.{0,1000}\s\-\-remote\s/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string2 = /\/ADCSPwn\.git/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string3 = /\\ADCSPwn/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string4 = /ADCSPwn\.csproj/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string5 = /ADCSPwn\.exe/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string6 = /ADCSPwn\.sln/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string7 = /ADCSPwn\-master/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string8 = /bats3c\/ADCSPwn/ nocase ascii wide

    condition:
        any of them
}
