rule havoc
{
    meta:
        description = "Detection patterns for the tool 'havoc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "havoc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string1 = /\shavoc\-client/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string2 = /\.\/donut\s.*\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string3 = /\.\/Havoc/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string4 = /\.\/havoc\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string5 = /\/Cracked5pider\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string6 = /\/demon\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string7 = /\/demon\.x64\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string8 = /\/demon1\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string9 = /\/demosyscalls\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string10 = /\/Dialogs\/Payload\.hpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string11 = /\/Havoc\.cpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string12 = /\/Havoc\.qss/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string13 = /\/Havoc\.rc/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string14 = /\/Havoc\/data\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string15 = /\/Havoc\/main\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string16 = /\/HavocFramework\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string17 = /\/HavocImages\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string18 = /\/havoc\-py\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string19 = /\/implants\/.*\/Syscalls\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string20 = /\/Jump\-exec\/Psexec/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string21 = /\/kerberoast\.c/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string22 = /\/kerberoast\.h/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string23 = /\/nanodump\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string24 = /\/payloads\/DllLdr\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string25 = /\/RemoteOps\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string26 = /\/scshell\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string27 = /\/Talon\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string28 = /\/Talon\/.*Agent\/Source/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string29 = /\/Widgets\/LootWidget\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string30 = /\/WMI\/wmi\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string31 = /\\demon\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string32 = /\\demon\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string33 = /\\demon\.x64\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string34 = /\\demon1\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string35 = /\\demosyscalls\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string36 = /\\Ekko\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string37 = /40056\/service\-endpoint/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string38 = /5spider:password1234/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string39 = /bin\/addusertogroup\.x64/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string40 = /bin\/setuserpass\.x64/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string41 = /Delegation\/delegation\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string42 = /DllLdr\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string43 = /Domaininfo\/Domaininfo\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string44 = /dotnet\sinline\-execute\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string45 = /externalc2\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string46 = /f5a45c4aa478a7ba9b44654a929bddc2f6453cd8d6f37cd893dda47220ad9870/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string47 = /havoc\sclient/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string48 = /havoc\sserver/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string49 = /havoc\.agent/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string50 = /Havoc\.git/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string51 = /Havoc\.hpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string52 = /havoc\.service/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string53 = /havoc\.yaotl/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string54 = /Havoc\/Client/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string55 = /Havoc\/cmd\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string56 = /Havoc\/payloads/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string57 = /Havoc\/pkg/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string58 = /Havoc\/Teamserver/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string59 = /havoc_agent\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string60 = /havoc_agent_talon\./ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string61 = /havoc_default\.yaotl/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string62 = /havoc_externalc2/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string63 = /havoc_service_connect/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string64 = /havoc\-c2\-client/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string65 = /havoc\-c2\-data/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string66 = /havocframework\.com/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string67 = /HavocService/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string68 = /HavocTalonInteract/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string69 = /HavocUi\.cpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string70 = /HavocUi\.h/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string71 = /HavocUI\.hpp/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string72 = /http.*\/demon\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string73 = /http.*\/demon\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string74 = /implant\.sleep\-obf/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string75 = /Implant\\SleepMask/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string76 = /inject\s1337\s\// nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string77 = /inject\.spawn/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string78 = /inject\.spoofaddr/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string79 = /Injection\\Spawn32/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string80 = /Injection\\Spawn64/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string81 = /InvokeAssembly\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string82 = /jump\-exec\spsexec\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string83 = /nanodump_ppl\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string84 = /nanodump_ssp\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string85 = /nanorobeus\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string86 = /powerpick\.py/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string87 = /PowerPick\.x64\.dll/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string88 = /PowershellRunner\.h/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string89 = /ServiceHavoc\.exe/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string90 = /set\shavoc\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string91 = /shellcode\sinject\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string92 = /shellcode\sspawn\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string93 = /Shellcode\.x64\.bin/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string94 = /token\sfind\-tokens/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string95 = /token\simpersonate\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string96 = /token\sprivs\-get/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string97 = /token\sprivs\-list/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string98 = /token\ssteal\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/its-a-feature/Mythic
        $string99 = /x\-ishavocframework/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string100 = /dcenum\s/ nocase ascii wide
        // Description: Havoc is a modern and malleable post-exploitation command and control framework
        // Reference: https://github.com/HavocFramework/Havoc
        $string101 = /powerpick\s/ nocase ascii wide

    condition:
        any of them
}