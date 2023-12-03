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
        $string1 = /.{0,1000}\sGhauri\sis\sgoing\sto\suse\sthe\scurrent\sdatabase\sto\senumerate\stable\(s\)\sentries.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string2 = /.{0,1000}\.py\s.{0,1000}\s\-\-sql\-shell.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string3 = /.{0,1000}\/dbms\/fingerprint\.py.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string4 = /.{0,1000}\/ghauri\.git.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string5 = /.{0,1000}\/ghauri\.py.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string6 = /.{0,1000}\/ghauri\/ghauri\/.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string7 = /.{0,1000}\\dbms\\fingerprint\.py.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string8 = /.{0,1000}\\ghauri\\ghauri\\.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string9 = /.{0,1000}\\ghauri\-1.{0,1000}\\ghauri\\.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string10 = /.{0,1000}A\scross\-platform\spython\sbased\sadvanced\ssql\sinjections\sdetection\s\&\sexploitation\stool.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string11 = /.{0,1000}calling\sMySQL\sshell\.\sTo\squit\stype\s\'x\'\sor\s\'q\'\sand\spress\sENTER.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string12 = /.{0,1000}Do\syou\swant\sGhauri\sset\sit\sfor\syou\s\?\s\[Y\/n\].{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string13 = /.{0,1000}Do\syou\swant\sto\sskip\stest\spayloads\sspecific\sfor\sother\sDBMSes\?.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string14 = /.{0,1000}ghauri\scurrently\sonly\ssupports\sDBMS\sfingerprint\spayloads\sfor\sMicrosoft\sAccess.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string15 = /.{0,1000}Ghauri\sdetected\sconnection\serrors\smultiple\stimes.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string16 = /.{0,1000}Ghauri\sis\sexpecting\sdatabase\sname\sto\senumerate\stable\(s\)\sentries.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string17 = /.{0,1000}ghauri\s\-u\s.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string18 = /.{0,1000}ghauri\-.{0,1000}\\ghauri\-.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string19 = /.{0,1000}ghauri\.common\.config.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string20 = /.{0,1000}ghauri\.common\.lib.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string21 = /.{0,1000}ghauri\.common\.payloads.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string22 = /.{0,1000}ghauri\.common\.session.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string23 = /.{0,1000}ghauri\.common\.utils.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string24 = /.{0,1000}ghauri\.core\.extract.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string25 = /.{0,1000}ghauri\.core\.tests.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string26 = /.{0,1000}ghauri\.extractor\.advance.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string27 = /.{0,1000}ghauri\.py\s.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string28 = /.{0,1000}ghauri_extractor.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string29 = /.{0,1000}ghauri\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string30 = /.{0,1000}http:\/\/www\.site\.com\/article\.php\?id\=1.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string31 = /.{0,1000}http:\/\/www\.site\.com\/vuln\.php\?id\=1\s\-\-dbs.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string32 = /.{0,1000}Nasir\sKhan\s\(r0ot\sh3x49\).{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string33 = /.{0,1000}r0oth3x49\/ghauri.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string34 = /.{0,1000}r0oth3x49\@gmail\.com.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string35 = /.{0,1000}scripts\/ghauri\.py.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string36 = /.{0,1000}scripts\\ghauri\.py.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string37 = /.{0,1000}sqlmapproject\/sqlmap\/issues\/2442.{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string38 = /.{0,1000}testing\sfor\sSQL\sinjection\son\s\(custom\).{0,1000}/ nocase ascii wide
        // Description: A cross-platform python based advanced sql injections detection & exploitation tool
        // Reference: https://github.com/r0oth3x49/ghauri
        $string39 = /.{0,1000}user\saborted\sduring\sDBMS\sfingerprint\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
