rule UnmanagedPowerShell
{
    meta:
        description = "Detection patterns for the tool 'UnmanagedPowerShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnmanagedPowerShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string1 = /\/UnmanagedPowerShell\.git/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string2 = /\\PowerShellRunnerDll\.h/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string3 = /\\UnmanagedPowerShell\.cpp/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string4 = /\\UnmanagedPowerShell\.exe/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string5 = /\\UnmanagedPowerShell\.sln/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string6 = /\\UnmanagedPowerShell\.vcxproj/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string7 = /5A9955E4\-62B7\-419D\-AB73\-01A6D7DD27FC/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string8 = /692110b2f60de3d52ac15e84be38fab5f9a16249b2bb0011af047b174efceeda/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string9 = /6EB55FE6\-C11C\-453B\-8B32\-22B689B6B3E2/ nocase ascii wide
        // Description: Executes PowerShell from an unmanaged process
        // Reference: https://github.com/leechristensen/UnmanagedPowerShell
        $string10 = /leechristensen\/UnmanagedPowerShell/ nocase ascii wide

    condition:
        any of them
}
