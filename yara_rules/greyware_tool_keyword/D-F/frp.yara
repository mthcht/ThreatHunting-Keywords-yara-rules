rule frp
{
    meta:
        description = "Detection patterns for the tool 'frp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "frp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string1 = /.{0,1000}\/frp\.git.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string2 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string3 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string4 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string5 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string6 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string7 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string8 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string9 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string10 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string11 = /.{0,1000}\/frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string12 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string13 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string14 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string15 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string16 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string17 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string18 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string19 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string20 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string21 = /.{0,1000}\\frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string22 = /.{0,1000}fatedier\/frp.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string23 = /.{0,1000}frpc\s\-c\s.{0,1000}frpc\.ini.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string24 = /.{0,1000}frpc\sreload\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string25 = /.{0,1000}frpc\sstatus\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string26 = /.{0,1000}frpc\sverify\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string27 = /.{0,1000}frpc_windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string28 = /.{0,1000}frpc_windows_arm64\.exe.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string29 = /.{0,1000}frps\s\-c\s.{0,1000}frps\.toml.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string30 = /.{0,1000}frps_windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string31 = /.{0,1000}frps_windows_arm64\.exe.{0,1000}/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string32 = /.{0,1000}ssh\s\-o\s\'proxycommand\ssocat\s\-\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
