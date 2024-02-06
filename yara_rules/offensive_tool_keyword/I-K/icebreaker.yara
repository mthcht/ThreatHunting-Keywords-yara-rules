rule icebreaker
{
    meta:
        description = "Detection patterns for the tool 'icebreaker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icebreaker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string1 = /\sicebreaker\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string2 = /\s\-oA\sicebreaker\-scan/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string3 = /\s\-\-password\-list\s/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string4 = /\s\-\-script\ssmb\-security\-mode.{0,1000}smb\-enum\-shares\s/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string5 = /\ssmb\-cmds\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string6 = /\.py.{0,1000}found\-users\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string7 = /\/DanMcInerney\/ridenum/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string8 = /\/DeathStar\/DeathStar\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string9 = /\/icebreaker\.git/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string10 = /\/icebreaker\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string11 = /\/lgandx\/Responder/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string12 = /\/opt\/icebreaker/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string13 = /\/Responder\/Responder\.conf/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string14 = /\/ridenum\/ridenum\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string15 = /\/shares\-with\-SCF\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string16 = /\/smb\-cmds\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string17 = /\/smb\-signing\-disabled\-hosts\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string18 = /\/theHarvester\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string19 = /\/virtualenvs\/icebreaker/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string20 = /\\icebreaker\.py/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string21 = /1mil\-AD\-passwords\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string22 = /byt3bl33d3r\/DeathStar/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string23 = /CoreSecurity\/impacket\// nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string24 = /DanMcInerney\/Empire/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string25 = /DanMcInerney\/icebreaker/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string26 = /DanMcInerney\/theHarvester/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string27 = /found\-passwords\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string28 = /https\:\/\/0\.0\.0\.0\:1337/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string29 = /icebreaker\:P\@ssword123456/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string30 = /icebreaker\-master\.zip/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string31 = /icebreaker\-scan\.xml/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string32 = /Invoke\-Cats\s\-pwds/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string33 = /Invoke\-Cats\.ps1/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string34 = /Invoke\-Pwds\.ps1/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string35 = /logs\/Responder\-Session\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string36 = /logs\/ridenum\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string37 = /logs\/shares\-with\-SCF\.txt/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string38 = /logs\/theHarvester\.py\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string39 = /net\slocalgroup\sadministrators\sicebreaker/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string40 = /net\suser\s\/add\sicebreaker\s/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string41 = /ntlmrelayx\.py\.log/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string42 = /sudo\stmux\snew\s\-s\sicebreaker/ nocase ascii wide
        // Description: Gets plaintext Active Directory credentials if you're on the internal network but outside the AD environment
        // Reference: https://github.com/DanMcInerney/icebreaker
        $string43 = /\-\-wordlist\=.{0,1000}\-passwords\.txt/ nocase ascii wide

    condition:
        any of them
}
