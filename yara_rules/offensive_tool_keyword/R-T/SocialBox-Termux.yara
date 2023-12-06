rule SocialBox_Termux
{
    meta:
        description = "Detection patterns for the tool 'SocialBox-Termux' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SocialBox-Termux"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string1 = /\sinstabf\.py/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string2 = /\sinstainsane\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string3 = /\sinstall\-sb\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string4 = /\sinsTof\.py/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string5 = /\sSocialBox\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string6 = /\stweetshell\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string7 = /\/fb\-brute\.pl/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/Ha3MrX/Gemail-Hack
        $string8 = /\/Gemail\-Hack\.git/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string9 = /\/insta\-bf\.git/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string10 = /\/instabf\.py/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string11 = /\/instainsane\.git/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string12 = /\/instainsane\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string13 = /\/install\-sb\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string14 = /\/insTof\.py/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string15 = /\/SocialBox\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string16 = /\/SocialBox\-Termux/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string17 = /\/Sup3r\-Us3r\/scripts\// nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string18 = /\/tweetshell\.sh/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string19 = /\/umeshshinde19\/instainsane/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string20 = /apt\-get\s\-y\sinstall\stor\s/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string21 = /Brute\-force\-Instagram\-.{0,1000}\.git/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string22 = /datr\=80ZzUfKqDOjwL8pauwqMjHTa/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/Ha3MrX/Gemail-Hack
        $string23 = /gemailhack\.py/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/Ha3MrX/Gemail-Hack
        $string24 = /Ha3MrX\/Gemail\-Hack/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string25 = /Ox\-Bruter\.pl/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string26 = /thelinuxchoice\/tweetshell/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string27 = /Yuuup\!\!\sPass\sCracked/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string28 = /ZxKmz4hXp6XKmTPg9lzgYxXN4sFr2pzo/ nocase ascii wide

    condition:
        any of them
}
