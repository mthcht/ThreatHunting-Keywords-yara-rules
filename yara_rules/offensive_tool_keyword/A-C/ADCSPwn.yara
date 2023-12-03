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
        $string1 = /.{0,1000}\.exe\s\-\-adcs\s.{0,1000}\s\-\-remote\s.{0,1000}/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string2 = /.{0,1000}\/ADCSPwn\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string3 = /.{0,1000}\\ADCSPwn.{0,1000}/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string4 = /.{0,1000}ADCSPwn\.csproj.{0,1000}/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string5 = /.{0,1000}ADCSPwn\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string6 = /.{0,1000}ADCSPwn\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string7 = /.{0,1000}ADCSPwn\-master.{0,1000}/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string8 = /.{0,1000}bats3c\/ADCSPwn.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
