rule dialupass
{
    meta:
        description = "Detection patterns for the tool 'dialupass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dialupass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string1 = /\\Dialupass\.cfg/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string2 = /1e3ec12fbe9825c1eb044994d27c6fb97e5b2cee352d114b0ae6f8862e2a2dd5/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string3 = /598555a7e053c7456ee8a06a892309386e69d473c73284de9bbc0ba73b17e70a/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string4 = /Dialup\/VPN\sPassword\sRecovery/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string5 = /Dialup\/VPN\sPasswords\sList/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string6 = /Dialupass\.exe/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string7 = /Dialupass\.zip/ nocase ascii wide

    condition:
        any of them
}
