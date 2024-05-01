rule wraith
{
    meta:
        description = "Detection patterns for the tool 'wraith' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wraith"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string1 = /\swraith\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string2 = /\swraith\-server\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string3 = /\swraith\-server_v.{0,1000}\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string4 = /\"active_wraith_clients\"/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string5 = /\/assets\/wraith\-scripts\// nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string6 = /\/wraith\.git/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string7 = /\/wraith\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string8 = /\/wraith\-master\.zip/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string9 = /\/wraith\-RAT\-payloads/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string10 = /\/wraith\-RAT\-payloads\.git/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string11 = /\/wraith\-server\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string12 = /\/wraith\-server_v.{0,1000}\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string13 = /\\wraith\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string14 = /\\wraith\-master\.zip/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string15 = /\\wraith\-RAT\-payloads/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string16 = /\\wraith\-server\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string17 = /\\wraith\-server_v.{0,1000}\.py/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string18 = /\<h1\>Wraith\sLogin/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string19 = /\<title\>Wraith\sLogin\<\/title\>/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string20 = /04eb0f500553c9d58de8f5a8bb102cba7dcb0d1e9a77baa4227237c49a5e81d8/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string21 = /309c23d800972611948a5980921fdf6e78bdda2fc4d30f4dba3bd8c970a17e94/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string22 = /76b70dcbcb1d45935f1b12eef38162b812f88bb4ff89a07a46609d879019103e/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string23 = /dev\.l1qu1d\.net\/wraith\-labs\/wraith/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string24 = /login\.php\?LOGMEOUTPLZ\=true/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string25 = /script_main\(wraith\,\scmdline\)/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string26 = /Successfully\sinstalled\swraith\sto\srun\son\sstartup\s/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string27 = /TR\-SLimey\/wraith\-RAT/ nocase ascii wide
        // Description: A free and open-source, modular Remote Administration Tool (RAT) / Payload Dropper written in Go(lang) with a flexible command and control (C2) system.
        // Reference: https://github.com/wraith-labs/wraith
        $string28 = /wraith\-labs\/wraith/ nocase ascii wide

    condition:
        any of them
}
