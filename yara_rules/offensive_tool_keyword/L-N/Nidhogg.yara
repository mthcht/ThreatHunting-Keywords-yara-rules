rule Nidhogg
{
    meta:
        description = "Detection patterns for the tool 'Nidhogg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nidhogg"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string1 = /\/Nidhogg\.cpp/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string2 = /\/Nidhogg\.exe/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string3 = /\/Nidhogg\.git/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string4 = /\/Nidhogg\.zip/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string5 = /\/NidhoggClient\.exe/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string6 = /\/NidhoggClient\// nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string7 = /\\\\\.\\Nidhogg/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string8 = /\\\\\?\?\\\\Nidhogg/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string9 = /\\\\Device\\\\Nidhogg/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string10 = /\\\\Device\\\\Nidhogg/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string11 = /\\\\Driver\\\\Nidhogg/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string12 = /\\Nidhogg\.cpp/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string13 = /\\Nidhogg\.exe/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string14 = /\\Nidhogg\.sln/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string15 = /\\Nidhogg\.sys/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string16 = /\\NidhoggClient\.exe/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string17 = /\\NidhoggClient\\/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string18 = /13C57810\-FF18\-4258\-ABC9\-935040A54F0B/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string19 = /CatalogFile\=Nidhogg\.cat/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string20 = /Idov31\/Nidhogg/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string21 = /include\s.{0,1000}Nidhogg\.hpp/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string22 = /Nidhogg\srootkit/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string23 = /Nidhogg.{0,1000}AntiAnalysis\.hpp/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string24 = /Nidhogg\:\:AntiAnalysis\:\:NidhoggDisableCallback/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string25 = /Nidhogg\:\:AntiAnalysis\:\:NidhoggEnableDisableEtwTi/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string26 = /Nidhogg\:\:AntiAnalysis\:\:NidhoggListObCallbacks/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string27 = /Nidhogg\:\:AntiAnalysis\:\:NidhoggListPsRoutines/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string28 = /Nidhogg\:\:AntiAnalysis\:\:NidhoggListRegistryCallbacks/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string29 = /Nidhogg\:\:AntiAnalysis\:\:NidhoggRestoreCallback/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string30 = /Nidhogg\:\:FileUtils\:\:NidhoggFileClearAllProtection/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string31 = /Nidhogg\:\:FileUtils\:\:NidhoggFileProtect/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string32 = /Nidhogg\:\:FileUtils\:\:NidhoggFileUnprotect/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string33 = /Nidhogg\:\:FileUtils\:\:NidhoggQueryFiles/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string34 = /Nidhogg\:\:ModuleUtils\:\:NidhoggAmsiBypass/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string35 = /Nidhogg\:\:ModuleUtils\:\:NidhoggETWBypass/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string36 = /Nidhogg\:\:ModuleUtils\:\:NidhoggInjectDll/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string37 = /Nidhogg\:\:ModuleUtils\:\:NidhoggInjectShellcode/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string38 = /Nidhogg\:\:ModuleUtils\:\:NidhoggPatchModule/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string39 = /Nidhogg\:\:ModuleUtils\:\:NidhoggReadData/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string40 = /Nidhogg\:\:ModuleUtils\:\:NidhoggWriteData/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string41 = /Nidhogg\:\:ProcessUtils\:\:NidhoggProcessClearAllProtection/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string42 = /Nidhogg\:\:ProcessUtils\:\:NidhoggProcessElevate/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string43 = /Nidhogg\:\:ProcessUtils\:\:NidhoggProcessHide/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string44 = /Nidhogg\:\:ProcessUtils\:\:NidhoggProcessProtect/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string45 = /Nidhogg\:\:ProcessUtils\:\:NidhoggProcessSetProtection/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string46 = /Nidhogg\:\:ProcessUtils\:\:NidhoggProcessUnhide/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string47 = /Nidhogg\:\:ProcessUtils\:\:NidhoggProcessUnprotect/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string48 = /Nidhogg\:\:ProcessUtils\:\:NidhoggQueryProcesses/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string49 = /Nidhogg\:\:ProcessUtils\:\:NidhoggQueryThreads/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string50 = /Nidhogg\:\:ProcessUtils\:\:NidhoggThreadHide/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string51 = /Nidhogg\:\:ProcessUtils\:\:NidhoggThreadProtect/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string52 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryClearAll/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string53 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryHideKey/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string54 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryHideValue/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string55 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryProtectKey/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string56 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryProtectValue/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string57 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryQueryHiddenKeys/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string58 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryQueryHiddenValues/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string59 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryQueryProtectedKeys/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string60 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryQueryProtectedValues/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string61 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryUnhideKey/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string62 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryUnhideValue/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string63 = /Nidhogg\:\:RegistryUtils\:\:NidhoggRegistryUnprotectValue/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string64 = /Nidhogg\-0\.1\.zip/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string65 = /Nidhogg\-0\.2\.zip/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string66 = /Nidhogg\-0\.3\.zip/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string67 = /Nidhogg\-0\.4\.zip/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string68 = /Nidhogg\-0\.5\.zip/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string69 = /NidhoggClient\.exe\s/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string70 = /NidhoggExample\.cpp/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string71 = /Nidhogg\-master/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string72 = /sc\sstart\snidhogg/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string73 = /tNidhoggClient\.exe/ nocase ascii wide

    condition:
        any of them
}
