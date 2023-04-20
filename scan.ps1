# Spør brukeren om subnettet eller IP-adressen som skal skannes
$subnet = Read-Host "Enter the subnet or IP address to scan (in CIDR format, e.g. 10.10.10.0/24):"

# Spør brukeren om portene som skal skannes
$ports = @()
$defaultPort = "443"
while ($true)
{
    $port = Read-Host "Enter a port to scan (default is $defaultPort, press Enter to continue):"
    if ($port -eq "")
    {
        if ($ports.Length -eq 0)
        {
            $ports += $defaultPort
        }
        break
    }
    else
    {
        $ports += $port
    }
}

# Spør brukeren om filnavnet for resultatene
$outputFile = Read-Host "Enter the output file name (default is ssl-certificates.csv):"
if ($outputFile -eq "")
{
    $outputFile = "ssl-certificates.csv"
}

# Funksjon for å sjekke om en port er åpen på en enhet
function Check-Port($ipAddress, $port)
{
    Write-Debug "Checking port $port on $ipAddress"
    $socket = New-Object Net.Sockets.TcpClient
    $asyncResult = $socket.BeginConnect($ipAddress, $port, $null, $null)
    $waitHandle = $asyncResult.AsyncWaitHandle
    try
    {
        if ($waitHandle.WaitOne(1000, $false))
        {
            $socket.EndConnect($asyncResult) | Out-Null
            Write-Debug "Port $port is open on $ipAddress"
            return $true
        }
        else
        {
            Write-Debug "Port $port is closed on $ipAddress"
            return $false
        }
    }
    catch
    {
        Write-Debug "Port $port is closed on $ipAddress (exception)"
        return $false
    }
    finally
    {
        $socket.Dispose()
        $waitHandle.Dispose()
    }
}

# Funksjon for å hente SSL-sertifikatet fra en enhet
function Get-SSLInfo($ipAddress, $port)
{
    Write-Debug "Getting SSL info for port $port on $ipAddress"
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try
    {
        $tcpClient.Connect($ipAddress, $port)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { param($sender, $cert, $chain, $sslPolicyErrors) $true })
        $sslStream.AuthenticateAsClient($ipAddress)
        $cert = $sslStream.RemoteCertificate
        if($cert -ne $null)
        {
            $subject = $cert.Subject
            $issuer = $cert.Issuer
            $validFrom = $cert.GetEffectiveDateString()
            $validTo = $cert.GetExpirationDateString()
            return $subject + "," + $issuer + "," + $validFrom + "," + $validTo
        }
    }
    catch
    {
        Write-Debug "Error getting SSL info for port $port on $ipAddress: $_.Exception.Message"
        return $null
    }
    finally
    {
        $tcpClient.Dispose()
    }
}

# Skanne en enkelt IP-adresse
function Scan-IPAddress($ipAddress, $ports)
{
    Write-Debug "Scanning IP address $ipAddress"
    $results = @()
    foreach ($port in $ports)
    {
        if (Check-Port $ipAddress $port)
        {
            $sslInfo = Get-SSLInfo $ipAddress $port
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $ipAddress
            $result | Add-Member -MemberType NoteProperty -Name "Port" -Value $port
            $result | Add-Member -MemberType NoteProperty -Name "SSL Certificate" -Value $sslInfo
            $results += $result
        }
    }
    return $results
}
# Skanne subnettet
function Scan-Subnet($subnet, $ports)
{
    Write-Debug "Scanning subnet $subnet"
    $results = @()
    for ($i = 1; $i -le 255; $i++)
    {
        $ipAddress = $subnet + "." + $i
        Write-Debug "Scanning IP address $ipAddress"
        $ipResults = Scan-IPAddress $ipAddress $ports
        $results += $ipResults
    }
    return $results
}
# Hovedprogram
if ($subnet -ne "" -and $ipAddress -ne "")
{
    Write-Error "You can only specify one of the 'subnet' and 'ipAddress' parameters."
}
elseif ($subnet -eq "" -and $ipAddress -eq "")
{
    $ipAddress = Read-Host "Enter the IP address to scan:"
}
elseif ($subnet -ne "")
{
    $ipAddress = $subnet
}

if ($ports.Length -eq 0)
{
    $ports += "443"
}

if ($ipAddress -like "*/*")
{
    # Skanne subnettet
    $results = Scan-Subnet $ipAddress $ports
}
else
{
    # Skanne enkelt IP-adresse
    $results = Scan-IPAddress $ipAddress $ports
}

# Lagre resultatene til CSV-filen
$results | Export-Csv $outputFile -NoTypeInformation

Write-Host "SSL certificate scan complete. Results saved to $outputFile."


