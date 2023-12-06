rule DoubleAgent
{
    meta:
        description = "Detection patterns for the tool 'DoubleAgent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoubleAgent"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DoubleAgent gives the attacker the ability to inject any DLL into any process. The code injection occurs extremely early during the victims process boot. giving the attacker full control over the process and no way for the process to protect itself. The code injection technique is so unique that its not detected or blocked by any antivirus.DoubleAgent can continue injecting code even after reboot making it a perfect persistence technique to survive reboots/updates/reinstalls/patches/etc. Once the attacker decides to inject a DLL into a process. they are forcefully bounded forever. Even if the victim would completely uninstall and reinstall its program. the attackers DLL would still be injected every time the process executes.
        // Reference: https://github.com/Cybellum/DoubleAgent
        $string1 = /DoubleAgent\.sln/ nocase ascii wide

    condition:
        any of them
}
