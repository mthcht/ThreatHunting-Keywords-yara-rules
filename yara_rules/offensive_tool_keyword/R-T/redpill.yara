rule redpill
{
    meta:
        description = "Detection patterns for the tool 'redpill' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redpill"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string1 = /\scleantracks\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string2 = /\sclipboard\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string3 = /\sDumpLsass\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string4 = /\sEnumBrowsers\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string5 = /\sFWUprank\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string6 = /\sGetPasswords\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string7 = /\sInvoke\-Dump\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string8 = /\slocalbrute\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string9 = /\s\-Mouselogger\sStart/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string10 = /\sNoAmsi\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string11 = /\sNSudo\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string12 = /\spapacat\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string13 = /\spapacat\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string14 = /\spapacat\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string15 = /\s\-PasswordSpray\s/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string16 = /\sPhishCreds\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string17 = /\sPingSweep\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string18 = /\spowercat\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string19 = /\sredpill\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string20 = /\srevshell\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string21 = /\sScanning\sEventvwr\sregistry\!\s\.\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string22 = /\s\-SmbLoginSpray\s/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string23 = /\s\-TaskName\sRedPillTask/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string24 = /\s\-UacMe\sElevate\s\-Execute\s/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string25 = /\swhoami\s\>\szzz\.txt/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string26 = /\sWinBruteLogon\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string27 = /\$DumpLsass\=/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string28 = /\$Env\:TMP\\Camera\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string29 = /\$Env\:TMP\\GetLogs\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string30 = /\$env\:TMP\\Leaked\.txt/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string31 = /\$Env\:TMP\\Screenshot\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string32 = /\$Env\:TMP\\StartWebServer\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string33 = /\$Env\:TMP\\Start\-WebServer\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string34 = /\$Env\:TMP\\tdfr\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string35 = /\$Env\:TMP\\Upload\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string36 = /\$Env\:TMP\\webserver\.ps1\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string37 = /\$Keylogger\=/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string38 = /\$SmbLoginSpray\=/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string39 = /\%tmp\%\\void\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string40 = /\.ps1\s\-StartWebServer\sPowershell/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string41 = /\.ps1\s\-StartWebServer\sPython/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string42 = /\.ps1\s\-WifiPasswords\sDump/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string43 = /\/cleantracks\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string44 = /\/CsOnTheFly\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string45 = /\/DumpLsass\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string46 = /\/FWUprank\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string47 = /\/GetPasswords\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string48 = /\/NSudo\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string49 = /\/papacat\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string50 = /\/papacat\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string51 = /\/PhishCreds\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string52 = /\/powercat\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string53 = /\/redpill\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string54 = /\/redpill\/bin\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string55 = /\/revshell\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string56 = /\/RunPEinMemory\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string57 = /\/RunPEinMemory64\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string58 = /\/ScanInterception\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string59 = /\/stext\scredentials\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string60 = /\/WinBruteLogon\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string61 = /\@Re\@mov\@e\-\@MpTh\@re\@at/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string62 = /\@redpill\sCS\sCompiled\sExecutable/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string63 = /\[START\]\:\sPassword\sspraying\sattack\!/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string64 = /\\AdsMasquerade\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string65 = /\\AppData\\Local\\Temp\\Camera\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string66 = /\\AppData\\Local\\Temp\\GetLogs\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string67 = /\\AppData\\Local\\Temp\\Leaked\.txt/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string68 = /\\AppData\\Local\\Temp\\Payload\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string69 = /\\AppData\\Local\\Temp\\Screenshot\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string70 = /\\AppData\\Local\\Temp\\SSIDump\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string71 = /\\AppData\\Local\\Temp\\Start\-WebServer\.\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string72 = /\\AppData\\Local\\Temp\\StartWebServer\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string73 = /\\AppData\\Local\\Temp\\Upload\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string74 = /\\AppData\\Local\\Temp\\webserver\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string75 = /\\BrowserEnum\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string76 = /\\BrowserLogger\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string77 = /\\BypassCredGuard\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string78 = /\\C2Prank\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string79 = /\\cleantracks\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string80 = /\\CleanTracks\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string81 = /\\clipboard\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string82 = /\\Clipboard\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string83 = /\\ConfuserEx\\Obfuscated\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string84 = /\\Convert\-ROT47\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string85 = /\\CookieHijack\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string86 = /\\credentials\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string87 = /\\CScrandle_fileless\.cs/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string88 = /\\CsOnTheFly\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string89 = /\\DecryptAutoLogon\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string90 = /\\DeletePSscriptSignning\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string91 = /\\DnSpoof\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string92 = /\\DumpLsass\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string93 = /\\enc\-rot13\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string94 = /\\EnumBrowsers\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string95 = /\\ETWpatch\\eventK\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string96 = /\\evil\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string97 = /\\FWUprank\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string98 = /\\GetAdmin\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string99 = /\\GetAdmin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string100 = /\\GetPasswords\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string101 = /\\gfscgsvs\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string102 = /\\identify_offencive_tools\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string103 = /\\Invoke\-Bypass\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string104 = /\\Invoke\-Dump\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string105 = /\\KeyDump\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string106 = /\\KeyDump\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string107 = /\\lnk_parser_cmd\.exe\s\-r\s/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string108 = /\\Lnk\-Sweeper\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string109 = /\\Lnk\-Sweeper\.txt/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string110 = /\\Local\\Temp\\logins\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string111 = /\\localbrute\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string112 = /\\maildump\.txt/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string113 = /\\Meterpeter_.{0,1000}\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string114 = /\\MineDownloader\.vbs/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string115 = /\\NoAmsi\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string116 = /\\NSudo\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string117 = /\\OutlookEmails\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string118 = /\\papacat\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string119 = /\\Persiste\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string120 = /\\Persistence\.vbs/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string121 = /\\PhishCreds\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string122 = /\\PingSweep\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string123 = /\\powercat\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string124 = /\\PSexecutionPolicy\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string125 = /\\psgetsys\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string126 = /\\pysecdump\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string127 = /\\r00t\-3xp10it/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string128 = /\\Rat\-x64\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string129 = /\\Rat\-x64\.lnk/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string130 = /\\redpill\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string131 = /\\redpill\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string132 = /\\redpill\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string133 = /\\redpill\\bin\\.{0,1000}\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string134 = /\\revshell\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string135 = /\\RunPEinMemory\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string136 = /\\RunPEinMemory64\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string137 = /\\ScanInterception\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string138 = /\\SelectMyParent\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string139 = /\\sendkeys\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string140 = /\\SigFlip\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string141 = /\\Smeagol\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string142 = /\\Temp\\Wdlogfile\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string143 = /\\URL_obfuscated\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string144 = /\\void\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string145 = /\\WinBruteLogon\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string146 = /\\windows\\temp\\fakefile\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string147 = /\\Xclipboard\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string148 = /\]\sDumping\sbrowsers\scredentials\s\.\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string149 = /\]\sDumping\smail\sserv\scredentials\s\.\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string150 = /\]\sDumping\smessenger\scredentials\s\.\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string151 = /\]\sSending\scredentials\sto\spastebin\s\.\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string152 = /\]\sto\sdownload\svoid\.zip\susing\sBitsTransfer/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string153 = /0evilpwfilter\.dll/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string154 = /Administrator\sprivileges\srequired\sto\sspoof\sprocesses/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string155 = /amibypass\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string156 = /amsibypass\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string157 = /amsitrigger_x64\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string158 = /bpysecdump\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string159 = /CommandCam\.exe\s\/devlist\s\>\s.{0,1000}\\CC\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string160 = /Crandle_Builder\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string161 = /CScrandle_fileless\.cs/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string162 = /DarkRCovery\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string163 = /DecodeRDPCache\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string164 = /DEL\s\/q\s\/f\s\%appdata\%\\Google\\Chrome\\\"User\sData\"\\Default\\.{0,1000}\.tmp/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string165 = /DEL\s\/q\s\/f\s\%appdata\%\\Google\\Chrome\\\"User\sData\"\\Default\\History\\.{0,1000}\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string166 = /DEL\s\/q\s\/f\s\%appdata\%\\Microsoft\\Windows\\Recent\\.{0,1000}\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string167 = /DEL\s\/q\s\/f\s\%windir\%\\.{0,1000}\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string168 = /DEL\s\/q\s\/f\s\%windir\%\\.{0,1000}\.tmp/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string169 = /DEL\s\/q\s\/f\s\%windir\%\\Prefetch\\.{0,1000}\.pf/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string170 = /DEL\s\/q\s\/f\s\%windir\%\\system\\.{0,1000}\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string171 = /DEL\s\/q\s\/f\s\%windir\%\\system\\.{0,1000}\.tmp/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string172 = /DEL\s\/q\s\/f\s\%windir\%\\system32\\.{0,1000}\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string173 = /DEL\s\/q\s\/f\s\%windir\%\\system32\\.{0,1000}\.tmp/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string174 = /DEL\s\/q\s\/f\s\%windir\%\\Temp\\.{0,1000}\.inf/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string175 = /DEL\s\/q\s\/f\s\%windir\%\\Temp\\.{0,1000}\.lnk/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string176 = /DEL\s\/q\s\/f\s\/s\s\%appdata\%\\Microsoft\\Windows\\Cookies\\.{0,1000}\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string177 = /DEL\s\/q\s\/f\s\/s\s\%appdata\%\\Microsoft\\Windows\\Cookies\\.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string178 = /DEL\s\/q\s\/f\s\/s\s\%appdata\%\\Microsoft\\Windows\\Recent\\.{0,1000}\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string179 = /DEL\s\/q\s\/f\s\/s\s\%appdata\%\\Mozilla\\Firefox\\Profiles\\.{0,1000}\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string180 = /DEL\s\/q\s\/f\s\/s\s\%userprofile\%\\.{0,1000}\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string181 = /DEL\s\/q\s\/f\s\/s\s\%userprofile\%\\.{0,1000}\.tmp/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string182 = /DeletePSscriptSignning\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string183 = /DigitalSignature\-Hijack\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string184 = /Disable\-AMS1\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string185 = /DisableDefender\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string186 = /DnsSpoof\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string187 = /DumpChromePasswords\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string188 = /Env\:TMP\\ACl\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string189 = /eviltree_x64\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string190 = /fail\sto\sretrieve\sSAM\shashs\!/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string191 = /FakeCmdLine\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string192 = /Fake\-Cmdline\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string193 = /HarvestBrowserPasswords\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string194 = /HarvestBrowserPasswords\.pdb/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string195 = /HiddenUser\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string196 = /How\-to\-bypass\-UAC\-in\-newer\-Windows\-versions\.html/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string197 = /Invoke\-HiveNightmare\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string198 = /Invoke\-LazySign\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string199 = /Invoke\-Mimikatz/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string200 = /Invoke\-PortScan/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string201 = /Invoke\-PuttyCreds/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string202 = /Invoke\-SAMDump/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string203 = /Invoke\-SendToPasteBin/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string204 = /Invoke\-WDigest\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string205 = /Invoke\-WebCamAvi\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string206 = /Key\`logger\srunning\sin\sbackground/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string207 = /Keylogger\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string208 = /List\-AllMailboxAndPST\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string209 = /meterpeter\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string210 = /Meterpeter_\$RandMe\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string211 = /Mouselogger\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string212 = /mozlz4\-win32\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string213 = /MpCmdRun\.exe\s\-RemoveDefinitions\s\-All/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string214 = /MyMeterpreter\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string215 = /Out\-PasteBin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string216 = /patch\-amsi\-x64\-powershell\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string217 = /PPIDSpoof\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string218 = /PrintNotifyPotato\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string219 = /PrintNotifyPotato\-NET2\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string220 = /r00t\-3xp10it\/venom\/master\/bin\/void\.zip/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string221 = /Reg\sAdd\s\'HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\'\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string222 = /REG\sDELETE\s\"HKCU\\Software\\Classes\\Local\sSettings\\Software\\Microsoft\\Windows\\Shell\\MuiCache\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string223 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Internet\sExplorer\\TypedPaths\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string224 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Internet\sExplorer\\TypedURLs\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string225 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppBadgeUpdated\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string226 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string227 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string228 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string229 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string230 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string231 = /REG\sDELETE\s\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps\"\s\/f/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string232 = /\-Rem\@ov\@eDef\@ini\@tio\@ns\s\-\@Al\@l/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string233 = /revTCPclient\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string234 = /RevTcpShell\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string235 = /ScanInterception_x64\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string236 = /Scanning\sConsoleHost_History\sfor\screds/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string237 = /Scanning\scredential\sstore\sfor\screds\!/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string238 = /Scanning\sregistry\sfor\swinlogon\screds/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string239 = /Scanning\sTeamviewer\sfor\screds\!/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string240 = /Scanning\swinlogon\sfor\scrypted\screds\!/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string241 = /Sending\sloot\sto\spastebin\swebserver\./ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string242 = /SendToPasteBin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string243 = /ServiceName.{0,1000}CorpVPN/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string244 = /SharpGhost\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string245 = /SharpGhosting\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string246 = /Show\-BallonTip\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string247 = /Show\-BalloonTip\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string248 = /Sigthief\.py/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string249 = /SilenceDefender\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string250 = /SilenceDefender_ATP\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string251 = /SilenceDefender_ATP\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string252 = /smblogin\.results\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string253 = /smblogin\.results\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string254 = /smblogin\-spray\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string255 = /Spray\-Passwords\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string256 = /Start\-SimpleHTTPServer\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string257 = /TeamViewerDecrypt\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string258 = /Temp\\graca\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string259 = /TestMyPrivs\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string260 = /\-u\sSSARedTeam\:s3cr3t/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string261 = /UACBypassCMSTP\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string262 = /vbs_obfuscator\.vbs/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string263 = /vbs_ofuscator\.vbs/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string264 = /vssadmin\sdelete\sshadows\s\/for\=\%systemdrive\%\s\/all\s\/quiet/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string265 = /WebBrowserPassView\.cfg/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string266 = /WebBrowserPassView\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string267 = /WebBrowserPassView\.pdb/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string268 = /WifiPasswords\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string269 = /WinBruteLogon\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string270 = /wtXx6sM1482OWfsMXon6Am4Hi01idvFNgog3jTCsyAA\=/ nocase ascii wide

    condition:
        any of them
}
