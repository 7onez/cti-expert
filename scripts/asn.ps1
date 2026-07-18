<#
asn.ps1 - native Windows ASN / IP / domain lookup (keyless, HTTPS-only).

A lightweight stand-in for nitefood/asn on Windows, where that tool needs a Unix
shell (it drives Unix `whois`, which Windows lacks). This uses only HTTPS APIs that
need no API key: ipwho.is for IP geolocation+ASN, RDAP (rdap.org) for authoritative
ASN registration, and bgp.tools / bgpview.io (best-effort) for announced prefixes.

Usage:
  asn 8.8.8.8              # IP    -> ASN, holder, rDNS, geo
  asn AS15169             # ASN   -> holder, range, announced prefixes
  asn 15169               # bare ASN number
  asn google.com          # domain-> resolve, then look up each IP
  asn 8.8.8.8 -Json       # raw JSON from the upstream API
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Target,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$UA = @{ 'User-Agent' = 'cti-expert-asn/1.0' }

function Get-Json { param([string]$Url) Invoke-RestMethod -Uri $Url -Headers $UA -TimeoutSec 20 }

function Write-Kv { param([string]$K, $V) if ($null -ne $V -and "$V" -ne "") { Write-Host ("  {0,-10} {1}" -f ($K + ":"), $V) } }

function Resolve-AsnPrefixes {
    # Best-effort announced-prefix list; skips silently if the API can't be reached.
    param([int]$Num)
    try {
        $r = Get-Json "https://api.bgpview.io/asn/$Num/prefixes"
        if ($r.status -eq 'ok') {
            return @($r.data.ipv4_prefixes.prefix) + @($r.data.ipv6_prefixes.prefix) | Where-Object { $_ }
        }
    } catch { }
    return @()
}

function Lookup-IP {
    param([string]$Ip)
    $r = Get-Json "https://ipwho.is/$Ip"
    if ($r.PSObject.Properties['success'] -and -not $r.success) { throw "ipwho.is: $($r.message)" }
    if ($Json) { return $r | ConvertTo-Json -Depth 8 }
    Write-Host ""
    Write-Host "IP $($r.ip)" -ForegroundColor Cyan
    Write-Kv "ASN"      $(if ($r.connection.asn) { "AS$($r.connection.asn)" })
    Write-Kv "Holder"   $r.connection.org
    Write-Kv "ISP"      $r.connection.isp
    Write-Kv "rDNS"     $r.connection.domain
    Write-Kv "Location" ("{0}{1}{2} [{3}]" -f $r.city, $(if ($r.city -and $r.country) { ", " }), $r.country, $r.country_code)
    Write-Kv "Type"     $r.type
}

function Lookup-ASN {
    param([int]$Num)
    $a = Get-Json "https://rdap.org/autnum/$Num"
    if ($Json) { return $a | ConvertTo-Json -Depth 8 }
    $holder = $null
    $ent = $a.entities | Select-Object -First 1
    if ($ent -and $ent.vcardArray) {
        $fn = $ent.vcardArray[1] | Where-Object { $_[0] -eq 'fn' } | Select-Object -First 1
        if ($fn) { $holder = $fn[3] }
    }
    Write-Host ""
    Write-Host "AS$Num" -ForegroundColor Cyan
    Write-Kv "Name"    $a.name
    Write-Kv "Holder"  $holder
    Write-Kv "Range"   $(if ($a.startAutnum) { "AS$($a.startAutnum)-AS$($a.endAutnum)" })
    Write-Kv "Handle"  $a.handle
    $prefixes = Resolve-AsnPrefixes -Num $Num
    if ($prefixes.Count) {
        Write-Kv "Prefixes" ("{0} announced" -f $prefixes.Count)
        $prefixes | Select-Object -First 20 | ForEach-Object { Write-Host "             $_" }
        if ($prefixes.Count -gt 20) { Write-Host "             ... (+$($prefixes.Count - 20) more; use -Json for all)" }
    }
}

# ---- dispatch by target type ---------------------------------------------
$t = $Target.Trim()
$ipRef = [ref]([System.Net.IPAddress]::None)
if ($t -match '^(?i:AS)?(\d{1,10})$') {
    Lookup-ASN -Num ([int]$Matches[1])
}
elseif ([System.Net.IPAddress]::TryParse($t, $ipRef)) {
    Lookup-IP -Ip $t
}
else {
    # Treat as a hostname: resolve to IPs, then look up each.
    try { $addrs = [System.Net.Dns]::GetHostAddresses($t) } catch { throw "Could not resolve '$t' (not an IP, ASN, or resolvable host)" }
    $ips = $addrs | Where-Object { $_.AddressFamily -in 'InterNetwork', 'InterNetworkV6' } | ForEach-Object { $_.IPAddressToString } | Select-Object -Unique
    if (-not $ips) { throw "No IP addresses for '$t'" }
    if ($Json) { $out = @{}; foreach ($ip in $ips) { $out[$ip] = (Get-Json "https://ipwho.is/$ip") }; return ($out | ConvertTo-Json -Depth 8) }
    Write-Host ""
    Write-Host "domain $t -> $($ips -join ', ')" -ForegroundColor DarkCyan
    foreach ($ip in $ips) { Lookup-IP -Ip $ip }
}
