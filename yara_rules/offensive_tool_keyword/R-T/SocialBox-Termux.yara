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
        $string1 = /.{0,1000}\sinstabf\.py.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string2 = /.{0,1000}\sinstainsane\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string3 = /.{0,1000}\sinstall\-sb\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string4 = /.{0,1000}\sinsTof\.py.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string5 = /.{0,1000}\sSocialBox\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string6 = /.{0,1000}\stweetshell\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string7 = /.{0,1000}\/fb\-brute\.pl.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/Ha3MrX/Gemail-Hack
        $string8 = /.{0,1000}\/Gemail\-Hack\.git.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string9 = /.{0,1000}\/insta\-bf\.git.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string10 = /.{0,1000}\/instabf\.py.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string11 = /.{0,1000}\/instainsane\.git.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string12 = /.{0,1000}\/instainsane\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string13 = /.{0,1000}\/install\-sb\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string14 = /.{0,1000}\/insTof\.py.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string15 = /.{0,1000}\/SocialBox\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string16 = /.{0,1000}\/SocialBox\-Termux.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string17 = /.{0,1000}\/Sup3r\-Us3r\/scripts\/.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string18 = /.{0,1000}\/tweetshell\.sh.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/umeshshinde19/instainsane
        $string19 = /.{0,1000}\/umeshshinde19\/instainsane.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string20 = /.{0,1000}apt\-get\s\-y\sinstall\stor\s.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string21 = /.{0,1000}Brute\-force\-Instagram\-.{0,1000}\.git.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string22 = /.{0,1000}datr\=80ZzUfKqDOjwL8pauwqMjHTa.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/Ha3MrX/Gemail-Hack
        $string23 = /.{0,1000}gemailhack\.py.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/Ha3MrX/Gemail-Hack
        $string24 = /.{0,1000}Ha3MrX\/Gemail\-Hack.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string25 = /.{0,1000}Ox\-Bruter\.pl.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/SocialBox-Termux
        $string26 = /.{0,1000}thelinuxchoice\/tweetshell.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://raw.githubusercontent.com/Sup3r-Us3r/scripts/master/fb-brute.pl
        $string27 = /.{0,1000}Yuuup\!\!\sPass\sCracked.{0,1000}/ nocase ascii wide
        // Description: SocialBox is a Bruteforce Attack Framework Facebook - Gmail - Instagram - Twitter for termux on android
        // Reference: https://github.com/samsesh/insta-bf
        $string28 = /.{0,1000}ZxKmz4hXp6XKmTPg9lzgYxXN4sFr2pzo.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
