rule Ahk2Exe
{
    meta:
        description = "Detection patterns for the tool 'Ahk2Exe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ahk2Exe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string1 = /\sAhk2Exe\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string2 = /\/Ahk2Exe\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string3 = /\/Ahk2Exe\.git/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string4 = /\/Ahk2Exe\.zip/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string5 = /\/Ahk2Exe1\..{0,1000}\.zip/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string6 = /\/ahk\-install\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string7 = /\/ahk\-v2\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string8 = /\/AutoHotkey_1.{0,1000}_setup\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string9 = /\/AutoHotkey_2.{0,1000}_setup\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string10 = /\/AutoHotkey64\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string11 = /\/releases\/download\/Ahk2Exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string12 = /\\Ahk2Exe\.ahk/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string13 = /\\Ahk2Exe\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string14 = /\\Ahk2Exe\.zip/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string15 = /\\AutoHotkey_1.{0,1000}_setup\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string16 = /\\AutoHotkey_2.{0,1000}_setup\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string17 = /\\AutoHotkey64\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string18 = /\\AutoHotkey64_UIA\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string19 = /\\AutoHotkeySC\.bin/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string20 = /\\AutoHotkeyU32\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string21 = /\\AutoHotkeyUX\.exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string22 = /\\Program\sFiles\\AutoHotkey/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string23 = /\\SetExeSubsystem\.ahk/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string24 = /\\SOFTWARE\\Classes\\\.ahk\\/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string25 = /\\SOFTWARE\\Classes\\AutoHotkeyScript\\/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string26 = /\\UX\\reset\-assoc\.ahk/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string27 = /\>AutoHotkey\sinstaller\</ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string28 = /\>AutoHotkey\sSetup\</ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string29 = /14a8b1ff0297c5f7c06c6ab36a257140c2f3d33e8c15a28e790d5039a29c00a7/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string30 = /41092e2433211a876f2b14f16a29fdae85a0d7e74565b23ab9e9c85bee892351/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string31 = /46d335c6ebda027aea00f5a8261b4d1a1763e17b858fe512bbe541f9bb66d464/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string32 = /4e1e3123dd85d3ac65a0803b08dd89b9b12b5a00b9f566782855332d03e5fe26/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string33 = /4f30ed7899506d15974d12e428f4647660f97a52cc21da06a6a295a06197bbd8/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string34 = /7a2aeb7256c40efa434c6fc95f920ee9b4555e526f2f7cd325b6dc482faa7c20/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string35 = /80840379e83b70528c541218023961323ae10cfd85b4a1dcf6bf0fc01a9336b7/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string36 = /80ce06d9341317b4c4b4b1e89b2f046e0426e1e952eaa9152231cc26a08de58f/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string37 = /9f2c7f990c554ba286616dd08e59ac32d543e80eef335f5c65762c020234bc1b/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string38 = /ab464ef9bfa3735111e4fbf0e21f34feecf29a66d8effce37814df6be1d8314b/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string39 = /AutoHotkey\/Ahk2Exe/ nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string40 = /https\:\/\/www\.autohotkey\.com\/download\// nocase ascii wide
        // Description: Official AutoHotkey script compiler - misused in scripting malicious executables
        // Reference: https://github.com/AutoHotkey/Ahk2Exe
        $string41 = /s\\AutoHotkey\sWindow\sSpy\.lnk/ nocase ascii wide

    condition:
        any of them
}
