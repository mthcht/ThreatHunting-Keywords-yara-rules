rule EASSniper
{
    meta:
        description = "Detection patterns for the tool 'EASSniper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EASSniper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string1 = /\sEASSniper\.ps1/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string2 = /\seas\-valid\-users\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string3 = /\sowa\-sprayed\-creds\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string4 = /\/EASSniper\.git/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string5 = /\/EASSniper\.ps1/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string6 = /\/eas\-valid\-users\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string7 = /\/owa\-sprayed\-creds\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string8 = /\\EASSniper\.ps1/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string9 = /\\eas\-valid\-users\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string10 = /\\owa\-sprayed\-creds\.txt/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string11 = /\]\sNow\sspraying\sEAS\sportal\sat\shttps\:\/\/.{0,1000}\/Microsoft\-Server\-ActiveSync/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string12 = /002fa7c3b308536f94ff10852afcfbb0285608d259a43277e69751ab7db48e04/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string13 = /fugawi\/EASSniper/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string14 = /Invoke\-PasswordSprayEAS/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string15 = /Invoke\-UsernameHarvestEAS/ nocase ascii wide
        // Description: EASSniper is a penetration testing tool for account enumeration and brute force attacks against Exchange Active Sync (EAS)
        // Reference: https://github.com/fugawi/EASSniper
        $string16 = /Password\sSpraying\sEAS\sat\shttps\:\/\// nocase ascii wide

    condition:
        any of them
}
