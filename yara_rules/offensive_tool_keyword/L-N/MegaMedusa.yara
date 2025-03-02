rule MegaMedusa
{
    meta:
        description = "Detection patterns for the tool 'MegaMedusa' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MegaMedusa"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string1 = "//Don't Recode & Decrypt it Niggas" nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string2 = "//MegaMedusa-DDoS-Machine" nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string3 = "685e710dd49930b791f10fe68c46a2eae0ecdd93191ceb459425b338a0980844" nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string4 = "777d789fe076804229d09cae4fd8abbab955c683ccc11195639b88cc6567786b" nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string5 = "a5c8d558af0e8e3853cdd03be91dc7d915113a291466383005dbe1951809f663" nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string6 = /com\/Anonym0usWork1221\/Free\-Proxies\/main\/proxy_files\/http_proxies\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string7 = /com\/Anonym0usWork1221\/Free\-Proxies\/main\/proxy_files\/https_proxies\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string8 = /com\/mmpx12\/proxy\-list\/master\/https\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string9 = /com\/monosans\/proxy\-list\/main\/proxies\/http\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string10 = /com\/MuRongPIG\/Proxy\-Master\/main\/http\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string11 = /com\/officialputuid\/KangProxy\/KangProxy\/http\/http\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string12 = /com\/opsxcq\/proxy\-list\/master\/list\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string13 = /com\/proxylist\-to\/proxy\-list\/main\/http\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string14 = /com\/prxchk\/proxy\-list\/main\/http\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string15 = /com\/roosterkid\/openproxylist\/main\/HTTPS_RAW\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string16 = /com\/ShiftyTR\/Proxy\-List\/master\/http\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string17 = /com\/ShiftyTR\/Proxy\-List\/master\/https\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string18 = /com\/TheSpeedX\/PROXY\-List\/master\/http\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string19 = /com\/yuceltoluyag\/GoodProxy\/main\/raw\.txt/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string20 = /http\:\/\/go\.mail\.ru\/search\?gay\.ru\.query\=1\&q\=\?abc\.r\&q\=/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string21 = /http\:\/\/king\-hrdevil\.rhcloud\.com\/f5ddos3\.html\?v\=/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string22 = /http\:\/\/louis\-ddosvn\.rhcloud\.com\/f5\.html\?v\=/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string23 = /http\:\/\/nova\.rambler\.ru\/search\?btnG\=\%D0\%9D\%\?D0\%B0\%D0\%B\&q\=/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string24 = /http\:\/\/page\-xirusteam\.rhcloud\.com\/f5ddos3\.html\?v\=/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string25 = /http\:\/\/php\-hrdevil\.rhcloud\.com\/f5ddos3\.html\?v\=/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string26 = /https\:\/\/codeberg\.org\/RipperSec\/MegaMedusa/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string27 = /https\:\/\/t\.me\/MegaMedusaLog/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string28 = /MegaMedusa\\x20Attacking/ nocase ascii wide
        // Description: MegaMedusa is DDoS tool using NodeJS language
        // Reference: https://github.com/TrashDono/MegaMedusa
        $string29 = /t\.me\/RipperSec\\x20\\x20\\x20\\x20\\x20\\x20\\x1b/ nocase ascii wide

    condition:
        any of them
}
