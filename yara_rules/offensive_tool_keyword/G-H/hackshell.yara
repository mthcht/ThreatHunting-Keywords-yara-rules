rule hackshell
{
    meta:
        description = "Detection patterns for the tool 'hackshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string1 = /\shackshell\.sh/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string2 = /\/hackshell\.sh/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string3 = /\/latest\/download\/linpeas\.sh/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string4 = /\/var\/tmp\/\.socket\s\-p\s\-c\s\\"exec\spython3\s\-c\s\\\\"import\sos\;os\.setuid\(0\)\;os\.setgid\(0\)\;os\.execl/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string5 = "79023345917d346447982c87eae5639171d2bc091505dc0869632440bcc250f2" nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string6 = "BASH_HISTORY=/dev/null exec -a " nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string7 = /burl\shttp\:\/\/ipinfo\.io\s2\>\/dev\/null/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string8 = /dl\shttp\:\/\/ipinfo\.io\s2\>\/dev\/nul/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string9 = "echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet" nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string10 = "hackerschoice/hackshell" nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string11 = /hackshell\-main\.zip/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string12 = /http\:\/\/37\.120\.235\.188\/blah\.tar\.gz/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string13 = /https\:\/\/bin\.ajam\.dev\/\/\$\(uname\s\-m\)\/bash/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string14 = /https\:\/\/github\.com\/hackerschoice\/thc\-tips\-tricks\-hacks\-cheat\-sheet\/raw\/master\/tools\/ghostip\.sh/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string15 = /https\:\/\/github\.com\/hackerschoice\/thc\-tips\-tricks\-hacks\-cheat\-sheet\/raw\/master\/tools\/whatserver\.sh/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string16 = /https\:\/\/thc\.org\/hs/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string17 = /nmap\s\-Pn\s\-p.{0,1000}\s\-\-open\s\-T4\s\-n\s\-oG\s\-\s.{0,1000}\s2\>\/dev\/null\s\|\sgrep\s\-F\sPorts/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string18 = /raw\.githubusercontent\.com\/peass\-ng\/PEASS\-ng\/master\/winPEAS\/winPEASps1\/winPEAS\.ps1/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string19 = /source\s\<\(curl\s\-SsfL\shttps\:\/\/thc\.org\/hs\)/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string20 = /SSH\-Hijack\s\(reptyr\)/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string21 = /tinyurl\.com\/haxshl/ nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string22 = "unset -f hs_init hs_init_alias hs_init_dl hs_init_shell" nocase ascii wide
        // Description: Make BASH stealthy and hacker friendly with lots of bash functions
        // Reference: https://github.com/hackerschoice/hackshell
        $string23 = "unset SSH_CLIENT SSH_CONNECTION; TERM=xterm-256color HISTFILE=/dev/null " nocase ascii wide

    condition:
        any of them
}
