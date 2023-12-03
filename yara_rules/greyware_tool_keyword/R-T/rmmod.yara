rule rmmod
{
    meta:
        description = "Detection patterns for the tool 'rmmod' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmmod"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string1 = /.{0,1000}rmmod\s\-r.{0,1000}/ nocase ascii wide
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string2 = /.{0,1000}rmmod\s\-\-remove.{0,1000}/ nocase ascii wide
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string3 = /.{0,1000}sudo\srmmod\s\-r.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
