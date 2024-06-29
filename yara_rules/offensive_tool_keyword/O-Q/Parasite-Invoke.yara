rule Parasite_Invoke
{
    meta:
        description = "Detection patterns for the tool 'Parasite-Invoke' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Parasite-Invoke"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string1 = /\sParasite\sInvoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string2 = /\.\sNice\sassembly\s\:D\s\./ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string3 = /\.exe\s\-\-path\sC\:\\\s\-r\s\-\-method\sVirtualAlloc/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string4 = /\/Parasite\sInvoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string5 = /\/Parasite\%20Invoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string6 = /\/Parasite\-Invoke\.git/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string7 = /\\Parasite\sInvoke\.csproj/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string8 = /\\Parasite\sInvoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string9 = /\\Parasite\sInvoke\.pdb/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string10 = /\\Parasite\sInvoke\.sln/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string11 = /\\Parasite\sInvoke\\/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string12 = /\\Parasite\-Invoke\-main/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string13 = /\=\=\=PARASITE\sINVOKE/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string14 = /7CEC7793\-3E22\-455B\-9E88\-94B8D1A8F78D/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string15 = /https\:\/\/pastebin\.com\/9JyjcMAH/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string16 = /https\:\/\/pastebin\.com\/iBeTbXCw/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string17 = /Michael\sZhmaylo\s\(github\.com\// nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string18 = /MzHmO\/Parasite\-Invoke/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string19 = /Parasite\sInvoke_\.\-\'/ nocase ascii wide

    condition:
        any of them
}
