rule bettercap
{
    meta:
        description = "Detection patterns for the tool 'bettercap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bettercap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string1 = /.{0,1000}\sbettercap.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string2 = /.{0,1000}\s\-caplet\s.{0,1000}\.cap/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string3 = /.{0,1000}\s\-eval\s.{0,1000}caplets\.update.{0,1000}\sui\.update.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string4 = /.{0,1000}\/arp_spoof\/.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string5 = /.{0,1000}\/bettercap.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string6 = /.{0,1000}\/c2\/c2\.go.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string7 = /.{0,1000}\/dns_grabber\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string8 = /.{0,1000}\/dns_spoof.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string9 = /.{0,1000}\/hid_inject\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string10 = /.{0,1000}\/hid_sniff\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string11 = /.{0,1000}\/ndp_spoof.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string12 = /.{0,1000}\/net_recon\/.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string13 = /.{0,1000}\/net_sniff\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string14 = /.{0,1000}\/net_sniff_.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string15 = /.{0,1000}\/wifi_hopping\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string16 = /.{0,1000}arp\.spoof\son.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string17 = /.{0,1000}arp\.spoof\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string18 = /.{0,1000}arp\.spoof\.targets.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string19 = /.{0,1000}arp_spoof\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string20 = /.{0,1000}ArpSpoofer.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string21 = /.{0,1000}bettercap\s.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string22 = /.{0,1000}bettercap\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string23 = /.{0,1000}bettercap_\.deb.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string24 = /.{0,1000}bettercap\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string25 = /.{0,1000}ble_recon\.go.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string26 = /.{0,1000}dhcp6\.spoof\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string27 = /.{0,1000}dns\.spoof\son.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string28 = /.{0,1000}dns\.spoof\.address.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string29 = /.{0,1000}dns\.spoof\.all.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string30 = /.{0,1000}dns\.spoof\.domains.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string31 = /.{0,1000}dns\.spoof\.hosts.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string32 = /.{0,1000}dns_spoof\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string33 = /.{0,1000}mac\.changer\son.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string34 = /.{0,1000}ndp_spoof\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string35 = /.{0,1000}net\.fuzz\s.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string36 = /.{0,1000}net\.fuzz\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string37 = /.{0,1000}net\.probe\son/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string38 = /.{0,1000}net\.probe\son.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string39 = /.{0,1000}net\.sniff\s.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string40 = /.{0,1000}net\.sniff\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string41 = /.{0,1000}net_recon\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string42 = /.{0,1000}wifi_fake_auth\..{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string43 = /.{0,1000}wifi_recon_handshakes.{0,1000}/ nocase ascii wide
        // Description: The Swiss Army knife for 802.11 -  BLE - IPv4 and IPv6 networks reconnaissance and MITM attacks.
        // Reference: https://github.com/bettercap/bettercap
        $string44 = /net\.recon\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
