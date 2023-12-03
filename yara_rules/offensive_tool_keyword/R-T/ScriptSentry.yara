rule ScriptSentry
{
    meta:
        description = "Detection patterns for the tool 'ScriptSentry' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScriptSentry"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string1 = /.{0,1000}\/ScriptSentry\.git.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string2 = /.{0,1000}\/ScriptSentry\.ps1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string3 = /.{0,1000}\/ScriptSentry\.psd1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string4 = /.{0,1000}\/ScriptSentry\.psm1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string5 = /.{0,1000}\\ScriptSentry\.ps1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string6 = /.{0,1000}\\ScriptSentry\.psd1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string7 = /.{0,1000}\\ScriptSentry\.psm1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string8 = /.{0,1000}\\ScriptSentry\.txt.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string9 = /.{0,1000}e1cd2b55\-3b4f\-41bd\-a168\-40db41e34349.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string10 = /.{0,1000}Find\-AdminLogonScripts\.ps1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string11 = /.{0,1000}Find\-LogonScriptCredentials\s\-LogonScripts.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string12 = /.{0,1000}Find\-LogonScriptCredentials\.ps1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string13 = /.{0,1000}Find\-UnsafeLogonScriptPermissions\.ps1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string14 = /.{0,1000}Find\-UnsafeUNCPermissions\s\-UNCScripts.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string15 = /.{0,1000}Find\-UnsafeUNCPermissions\.ps1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string16 = /.{0,1000}Get\-DomainAdmins\.ps1.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string17 = /.{0,1000}Invoke\-ScriptSentry.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string18 = /.{0,1000}ScriptSentry\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string19 = /.{0,1000}techspence\/ScriptSentry.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
