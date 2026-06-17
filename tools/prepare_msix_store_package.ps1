param(
    [Parameter(Mandatory=$true)][string]$StageDir,
    [Parameter(Mandatory=$true)][string]$AppName,
    [Parameter(Mandatory=$true)][string]$DisplayName,
    [Parameter(Mandatory=$true)][string]$Description,
    [Parameter(Mandatory=$true)][string]$IdentityName,
    [Parameter(Mandatory=$true)][string]$Publisher,
    [Parameter(Mandatory=$true)][string]$PublisherDisplayName,
    [Parameter(Mandatory=$true)][string]$Version,
    [string]$MinVersion = "10.0.17763.0",
    [string]$MaxVersionTested = "10.0.26100.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Escape-Xml([string]$Value) {
    return [System.Security.SecurityElement]::Escape($Value)
}

$stageFull = (Resolve-Path $StageDir).Path
$assetsDir = Join-Path $stageFull "Assets"
New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null

# Reuse a logo if present. Otherwise create simple generated assets.
$projectRoot = (Resolve-Path ".").Path
$logoCandidates = @(
    (Join-Path $projectRoot "assets\packetdesk_logo.png"),
    (Join-Path $projectRoot "assets\PacketDeskLogo.png"),
    (Join-Path $projectRoot "packetdesk_tech_dashboard_logo.png")
)
$sourceLogo = $logoCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

Add-Type -AssemblyName System.Drawing

function New-LogoAsset {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][int]$Width,
        [Parameter(Mandatory=$true)][int]$Height,
        [string]$SourceLogoPath
    )

    $bmp = New-Object System.Drawing.Bitmap($Width, $Height)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::FromArgb(16, 24, 32))

    if ($SourceLogoPath -and (Test-Path $SourceLogoPath)) {
        $src = [System.Drawing.Image]::FromFile($SourceLogoPath)
        try {
            $maxW = [int]($Width * 0.82)
            $maxH = [int]($Height * 0.82)
            $scale = [Math]::Min($maxW / $src.Width, $maxH / $src.Height)
            $drawW = [Math]::Max(1, [int]($src.Width * $scale))
            $drawH = [Math]::Max(1, [int]($src.Height * $scale))
            $x = [int](($Width - $drawW) / 2)
            $y = [int](($Height - $drawH) / 2)
            $g.DrawImage($src, $x, $y, $drawW, $drawH)
        }
        finally {
            $src.Dispose()
        }
    }
    else {
        $accent = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(64, 196, 128))
        $bluePen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(70, 145, 230), [Math]::Max(2, [int]($Width / 28)))
        $redPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(230, 70, 80), [Math]::Max(2, [int]($Width / 28)))
        $fontSize = [Math]::Max(10, [int]([Math]::Min($Width, $Height) * 0.30))
        $font = New-Object System.Drawing.Font("Segoe UI", $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
        $textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)

        $g.DrawEllipse($bluePen, [int]($Width*0.15), [int]($Height*0.30), [int]($Width*0.18), [int]($Height*0.18))
        $g.DrawLine($bluePen, [int]($Width*0.32), [int]($Height*0.39), [int]($Width*0.55), [int]($Height*0.55))
        $g.DrawEllipse($bluePen, [int]($Width*0.52), [int]($Height*0.46), [int]($Width*0.18), [int]($Height*0.18))
        $g.DrawLine($redPen, [int]($Width*0.72), [int]($Height*0.30), [int]($Width*0.76), [int]($Height*0.62))
        $g.FillEllipse($accent, [int]($Width*0.72), [int]($Height*0.50), [int]($Width*0.16), [int]($Height*0.16))

        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Center
        $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
        $rect = New-Object System.Drawing.RectangleF(0, [single]($Height*0.15), $Width, [single]($Height*0.70))
        $g.DrawString("PD", $font, $textBrush, $rect, $sf)

        $accent.Dispose(); $bluePen.Dispose(); $redPen.Dispose(); $font.Dispose(); $textBrush.Dispose(); $sf.Dispose()
    }

    $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
}

$assetSpecs = @(
    @{ Name = "Square44x44Logo.png"; Width = 44; Height = 44 },
    @{ Name = "Square71x71Logo.png"; Width = 71; Height = 71 },
    @{ Name = "Square150x150Logo.png"; Width = 150; Height = 150 },
    @{ Name = "Square310x310Logo.png"; Width = 310; Height = 310 },
    @{ Name = "StoreLogo.png"; Width = 50; Height = 50 },
    @{ Name = "Wide310x150Logo.png"; Width = 310; Height = 150 },
    @{ Name = "SplashScreen.png"; Width = 620; Height = 300 }
)

foreach ($spec in $assetSpecs) {
    New-LogoAsset -Path (Join-Path $assetsDir $spec.Name) -Width $spec.Width -Height $spec.Height -SourceLogoPath $sourceLogo
}

$xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
  xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  IgnorableNamespaces="uap uap10 rescap">

  <Identity
    Name="$(Escape-Xml $IdentityName)"
    Publisher="$(Escape-Xml $Publisher)"
    Version="$(Escape-Xml $Version)"
    ProcessorArchitecture="x64" />

  <Properties>
    <DisplayName>$(Escape-Xml $DisplayName)</DisplayName>
    <PublisherDisplayName>$(Escape-Xml $PublisherDisplayName)</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>

  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="$(Escape-Xml $MinVersion)" MaxVersionTested="$(Escape-Xml $MaxVersionTested)" />
  </Dependencies>

  <Resources>
    <Resource Language="en-us" />
  </Resources>

  <Applications>
    <Application
      Id="App"
      Executable="$(Escape-Xml $AppName)\$(Escape-Xml $AppName).exe"
      EntryPoint="Windows.FullTrustApplication"
      uap10:RuntimeBehavior="packagedClassicApp"
      uap10:TrustLevel="mediumIL">
      <uap:VisualElements
        DisplayName="$(Escape-Xml $DisplayName)"
        Description="$(Escape-Xml $Description)"
        BackgroundColor="#101820"
        Square44x44Logo="Assets\Square44x44Logo.png"
        Square150x150Logo="Assets\Square150x150Logo.png">
        <uap:DefaultTile
          Square71x71Logo="Assets\Square71x71Logo.png"
          Wide310x150Logo="Assets\Wide310x150Logo.png"
          Square310x310Logo="Assets\Square310x310Logo.png" />
        <uap:SplashScreen Image="Assets\SplashScreen.png" BackgroundColor="#101820" />
      </uap:VisualElements>
    </Application>
  </Applications>

  <Capabilities>
    <Capability Name="internetClient" />
    <Capability Name="privateNetworkClientServer" />
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
"@

$manifestPath = Join-Path $stageFull "AppxManifest.xml"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestPath, $xml, $utf8NoBom)
Write-Host "Created $manifestPath"
Write-Host "Created MSIX assets in $assetsDir"
if ($sourceLogo) {
    Write-Host "Used source logo: $sourceLogo"
}
else {
    Write-Host "No logo found; generated simple PacketDesk placeholder assets."
}
