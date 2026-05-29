Detects obfuscated PowerShell commonly used after phishing compromise.

rule APT35_PowerShell_Dropper
{
    meta:
        description = "Detects PowerShell-based payload delivery and obfuscation"
        category = "Execution / Dropper"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-enc" nocase
        $ps3 = "IEX" nocase
        $ps4 = "Invoke-Expression" nocase
        $ps5 = "DownloadString" nocase
        $ps6 = "Net.WebClient" nocase

    condition:
        2 of ($ps2, $ps3, $ps4, $ps5, $ps6)
}
