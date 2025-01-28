rule DecryptAutoLogon
{
    meta:
        description = "Detection patterns for the tool 'DecryptAutoLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptAutoLogon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string1 = /\/DecryptAutoLogon\.exe/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string2 = /\/DecryptAutoLogon\.git/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string3 = /\\DecryptAutoLogon\.exe/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string4 = /\\DecryptAutoLogon\.sln/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string5 = /\\DecryptAutoLogon\.sln/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string6 = /\\DecryptAutoLogon\-main/ nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string7 = ">DecryptAutoLogon<" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string8 = "015A37FC-53D0-499B-BFFE-AB88C5086040" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string9 = "6f14aa417bc4b85c47ef65bfed84e2b7728b1cb8bdd1c0cfc6eb6cd7fd0db7c0" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string10 = "83b65d33d21b01395de5b5537e36f18eb8f16237a64f3a8f17991dc652d1a61a" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string11 = "83b65d33d21b01395de5b5537e36f18eb8f16237a64f3a8f17991dc652d1a61a" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string12 = "9b723acfd67b3a99b88251493db23b8af6fedc8e36395096acec7332f61b86ba" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string13 = "c749894ea43c267418df93c7dd6b74ef25826d6c4a5461226ec800ae2efd1921" nocase ascii wide
        // Description: Command line tool to extract/decrypt the password that was stored in the LSA by SysInternals AutoLogon
        // Reference: https://github.com/securesean/DecryptAutoLogon
        $string14 = "securesean/DecryptAutoLogon" nocase ascii wide

    condition:
        any of them
}
