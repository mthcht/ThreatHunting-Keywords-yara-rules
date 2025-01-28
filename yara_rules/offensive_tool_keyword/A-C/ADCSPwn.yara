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
        $string4 = ">ADCSPwn<" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string5 = "0bb4b892f67fdf903ed5e5df2c85c5ccb71669c298736cf24284412de435509a" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string6 = "980EF05F-87D1-4A0A-932A-582FB1BC3AC3" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string7 = /ADCSPwn\.csproj/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string8 = /ADCSPwn\.exe/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string9 = /ADCSPwn\.sln/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string10 = /ADCSPwn\.zip/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string11 = "ADCSPwn-master" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string12 = "bats3c/ADCSPwn" nocase ascii wide

    condition:
        any of them
}
