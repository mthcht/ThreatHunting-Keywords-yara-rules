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
        $string1 = /\/ScriptSentry\.git/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string2 = /\/ScriptSentry\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string3 = /\/ScriptSentry\.psd1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string4 = /\/ScriptSentry\.psm1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string5 = /\\ScriptSentry\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string6 = /\\ScriptSentry\.psd1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string7 = /\\ScriptSentry\.psm1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string8 = /\\ScriptSentry\.txt/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string9 = /e1cd2b55\-3b4f\-41bd\-a168\-40db41e34349/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string10 = /Find\-AdminLogonScripts\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string11 = /Find\-LogonScriptCredentials\s\-LogonScripts/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string12 = /Find\-LogonScriptCredentials\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string13 = /Find\-UnsafeLogonScriptPermissions\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string14 = /Find\-UnsafeUNCPermissions\s\-UNCScripts/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string15 = /Find\-UnsafeUNCPermissions\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string16 = /Get\-DomainAdmins\.ps1/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string17 = /Invoke\-ScriptSentry/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string18 = /ScriptSentry\-main\.zip/ nocase ascii wide
        // Description: ScriptSentry finds misconfigured and dangerous logon scripts.
        // Reference: https://github.com/techspence/ScriptSentry
        $string19 = /techspence\/ScriptSentry/ nocase ascii wide

    condition:
        any of them
}
