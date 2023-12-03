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
        $string1 = /.{0,1000}\/Nidhogg\.cpp.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string2 = /.{0,1000}\/Nidhogg\.exe.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string3 = /.{0,1000}\/Nidhogg\.git.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string4 = /.{0,1000}\/Nidhogg\.zip.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string5 = /.{0,1000}\/NidhoggClient\.exe.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string6 = /.{0,1000}\/NidhoggClient\/.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string7 = /.{0,1000}\\\\\.\\Nidhogg.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string8 = /.{0,1000}\\\\\?\?\\\\Nidhogg.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string9 = /.{0,1000}\\\\Device\\\\Nidhogg.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string10 = /.{0,1000}\\\\Device\\\\Nidhogg.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string11 = /.{0,1000}\\\\Driver\\\\Nidhogg.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string12 = /.{0,1000}\\Nidhogg\.cpp.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string13 = /.{0,1000}\\Nidhogg\.exe.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string14 = /.{0,1000}\\Nidhogg\.sln.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string15 = /.{0,1000}\\Nidhogg\.sys.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string16 = /.{0,1000}\\NidhoggClient\.exe.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string17 = /.{0,1000}\\NidhoggClient\\.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string18 = /.{0,1000}13C57810\-FF18\-4258\-ABC9\-935040A54F0B.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string19 = /.{0,1000}CatalogFile\=Nidhogg\.cat.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string20 = /.{0,1000}Idov31\/Nidhogg.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string21 = /.{0,1000}include\s.{0,1000}Nidhogg\.hpp.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string22 = /.{0,1000}Nidhogg\srootkit.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string23 = /.{0,1000}Nidhogg.{0,1000}AntiAnalysis\.hpp.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string24 = /.{0,1000}Nidhogg::AntiAnalysis::NidhoggDisableCallback.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string25 = /.{0,1000}Nidhogg::AntiAnalysis::NidhoggEnableDisableEtwTi.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string26 = /.{0,1000}Nidhogg::AntiAnalysis::NidhoggListObCallbacks.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string27 = /.{0,1000}Nidhogg::AntiAnalysis::NidhoggListPsRoutines.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string28 = /.{0,1000}Nidhogg::AntiAnalysis::NidhoggListRegistryCallbacks.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string29 = /.{0,1000}Nidhogg::AntiAnalysis::NidhoggRestoreCallback.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string30 = /.{0,1000}Nidhogg::FileUtils::NidhoggFileClearAllProtection.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string31 = /.{0,1000}Nidhogg::FileUtils::NidhoggFileProtect.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string32 = /.{0,1000}Nidhogg::FileUtils::NidhoggFileUnprotect.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string33 = /.{0,1000}Nidhogg::FileUtils::NidhoggQueryFiles.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string34 = /.{0,1000}Nidhogg::ModuleUtils::NidhoggAmsiBypass.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string35 = /.{0,1000}Nidhogg::ModuleUtils::NidhoggETWBypass.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string36 = /.{0,1000}Nidhogg::ModuleUtils::NidhoggInjectDll.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string37 = /.{0,1000}Nidhogg::ModuleUtils::NidhoggInjectShellcode.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string38 = /.{0,1000}Nidhogg::ModuleUtils::NidhoggPatchModule.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string39 = /.{0,1000}Nidhogg::ModuleUtils::NidhoggReadData.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string40 = /.{0,1000}Nidhogg::ModuleUtils::NidhoggWriteData.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string41 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggProcessClearAllProtection.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string42 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggProcessElevate.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string43 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggProcessHide.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string44 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggProcessProtect.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string45 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggProcessSetProtection.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string46 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggProcessUnhide.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string47 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggProcessUnprotect.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string48 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggQueryProcesses.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string49 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggQueryThreads.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string50 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggThreadHide.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string51 = /.{0,1000}Nidhogg::ProcessUtils::NidhoggThreadProtect.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string52 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryClearAll.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string53 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryHideKey.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string54 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryHideValue.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string55 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryProtectKey.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string56 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryProtectValue.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string57 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenKeys.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string58 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryQueryHiddenValues.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string59 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedKeys.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string60 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryQueryProtectedValues.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string61 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryUnhideKey.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string62 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryUnhideValue.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string63 = /.{0,1000}Nidhogg::RegistryUtils::NidhoggRegistryUnprotectValue.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string64 = /.{0,1000}Nidhogg\-0\.1\.zip.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string65 = /.{0,1000}Nidhogg\-0\.2\.zip.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string66 = /.{0,1000}Nidhogg\-0\.3\.zip.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string67 = /.{0,1000}Nidhogg\-0\.4\.zip.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string68 = /.{0,1000}Nidhogg\-0\.5\.zip.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string69 = /.{0,1000}NidhoggClient\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string70 = /.{0,1000}NidhoggExample\.cpp.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string71 = /.{0,1000}Nidhogg\-master.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string72 = /.{0,1000}sc\sstart\snidhogg.{0,1000}/ nocase ascii wide
        // Description: Nidhogg is an all-in-one simple to use rootkit for red teams.
        // Reference: https://github.com/Idov31/Nidhogg
        $string73 = /.{0,1000}tNidhoggClient\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
