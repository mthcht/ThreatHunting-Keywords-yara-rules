rule ghauri
{
    meta:
        description = "Detection patterns for the tool 'ghauri' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghauri"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string1 = /\sGhauri\sis\sgoing\sto\suse\sthe\scurrent\sdatabase\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string2 = /\.py\s.{0,1000}\s\-\-sql\-shell/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string3 = /\/dbms\/fingerprint\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string4 = /\/ghauri\.git/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string5 = /\/ghauri\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string6 = /\/ghauri\/ghauri\// nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string7 = /\\dbms\\fingerprint\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string8 = /\\ghauri\\ghauri\\/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string9 = /\\ghauri\-1.{0,1000}\\ghauri\\/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string10 = /A\scross\-platform\spython\sbased\sadvanced\ssql\sinjections\sdetection\s\&\sexploitation\stool/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string11 = /calling\sMySQL\sshell\.\sTo\squit\stype\s\'x\'\sor\s\'q\'\sand\spress\sENTER/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string12 = /Do\syou\swant\sGhauri\sset\sit\sfor\syou\s\?\s\[Y\/n\]/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string13 = /Do\syou\swant\sto\sskip\stest\spayloads\sspecific\sfor\sother\sDBMSes\?/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string14 = /ghauri\scurrently\sonly\ssupports\sDBMS\sfingerprint\spayloads\sfor\sMicrosoft\sAccess/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string15 = /Ghauri\sdetected\sconnection\serrors\smultiple\stimes/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string16 = /Ghauri\sis\sexpecting\sdatabase\sname\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string17 = /ghauri\s\-u\s/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string18 = /ghauri\-.{0,1000}\\ghauri\-/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string19 = /ghauri\.common\.config/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string20 = /ghauri\.common\.lib/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string21 = /ghauri\.common\.payloads/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string22 = /ghauri\.common\.session/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string23 = /ghauri\.common\.utils/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string24 = /ghauri\.core\.extract/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string25 = /ghauri\.core\.tests/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string26 = /ghauri\.extractor\.advance/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string27 = /ghauri\.py\s/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string28 = /ghauri_extractor/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string29 = /ghauri\-main\.zip/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string30 = /http\:\/\/www\.site\.com\/article\.php\?id\=1/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string31 = /http\:\/\/www\.site\.com\/vuln\.php\?id\=1\s\-\-dbs/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string32 = /Nasir\sKhan\s\(r0ot\sh3x49\)/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string33 = /r0oth3x49\/ghauri/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string34 = /r0oth3x49\@gmail\.com/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string35 = /scripts\/ghauri\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string36 = /scripts\\ghauri\.py/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string37 = /sqlmapproject\/sqlmap\/issues\/2442/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string38 = /testing\sfor\sSQL\sinjection\son\s\(custom\)/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string39 = /user\saborted\sduring\sDBMS\sfingerprint\./ nocase ascii wide

    condition:
        any of them
}
