<?php

class DNSRecordType {
    const A = 1;
    const NS = 2;
    const CNAME = 5;
    const SOA = 6;
    const PTR = 12;
    const MX = 15;
    const TXT = 16;
    const AAAA = 28;
    const SRV = 33;
    const DNAME = 39;
    const DS = 43;
    const RRSIG = 46;
    const NSEC = 47;
    const DNSKEY = 48;
    const HTTPS = 65;
    const ANY = 255;

    public static function getName(int $type): string {
        $map = [
            self::A => 'A',
            self::NS => 'NS',
            self::CNAME => 'CNAME',
            self::SOA => 'SOA',
            self::PTR => 'PTR',
            self::MX => 'MX',
            self::TXT => 'TXT',
            self::AAAA => 'AAAA',
            self::SRV => 'SRV',
            self::DNAME => 'DNAME',
            self::DS => 'DS',
            self::RRSIG => 'RRSIG',
            self::NSEC => 'NSEC',
            self::DNSKEY => 'DNSKEY',
            self::HTTPS => 'HTTPS',
            self::ANY => 'ANY'
        ];
        return $map[$type] ?? 'UNKNOWN';
    }
}

class DNSRecord {
    public string $name;
    public int $type;
    public int $ttl;
    public $data;
    public string $section;
    public ?int $preference;
    public ?string $rdata;
    public ?float $cacheTime;

    public function __construct(
        string $name,
        int $type,
        int $ttl,
        $data,
        string $section = "answer",
        ?int $preference = null,
        ?string $rdata = null,
        ?float $cacheTime = null
    ) {
        $this->name = $name;
        $this->type = $type;
        $this->ttl = $ttl;
        $this->data = $data;
        $this->section = $section;
        $this->preference = $preference;
        $this->rdata = $rdata;
        $this->cacheTime = $cacheTime;
    }

    public function getRemainingTTL(): int {
        if ($this->cacheTime === null) {
            return $this->ttl;
        }
        $elapsed = microtime(true) - $this->cacheTime;
        $remaining = $this->ttl - (int)$elapsed;
        return max(0, $remaining);
    }

    public function __toString(): string {
        $typeStr = DNSRecordType::getName($this->type);
        $ttlDisplay = $this->cacheTime ? $this->getRemainingTTL() : $this->ttl;

        switch ($this->type) {
            case DNSRecordType::MX:
                return sprintf("%s\t%d\t%d\t%s", $typeStr, $ttlDisplay, $this->preference, $this->data);
            case DNSRecordType::SOA:
                $soa = $this->data;
                return sprintf("%s\t%d\t%s %s (%d %d %d %d %d)", 
                    $typeStr, $ttlDisplay, 
                    $soa['mname'], $soa['rname'],
                    $soa['serial'], $soa['refresh'], $soa['retry'],
                    $soa['expire'], $soa['minimum']);
            case DNSRecordType::TXT:
                return sprintf("%s\t%d\t\"%s\"", $typeStr, $ttlDisplay, $this->data);
            case DNSRecordType::SRV:
                $srv = $this->data;
                return sprintf("%s\t%d\t%d %d %d %s", 
                    $typeStr, $ttlDisplay,
                    $srv['priority'], $srv['weight'], $srv['port'], $srv['target']);
            default:
                return sprintf("%s\t%d\t%s", $typeStr, $ttlDisplay, $this->data);
        }
    }

    public function toArray(): array {
        $result = [
            'name' => $this->name,
            'type' => DNSRecordType::getName($this->type),
            'ttl' => $this->ttl,
            'remaining_ttl' => $this->getRemainingTTL(),
            'section' => $this->section
        ];

        switch ($this->type) {
            case DNSRecordType::MX:
                $result['preference'] = $this->preference;
                $result['exchange'] = $this->data;
                break;
            case DNSRecordType::SOA:
                $result = array_merge($result, $this->data);
                break;
            case DNSRecordType::SRV:
                $result = array_merge($result, $this->data);
                break;
            default:
                $result['data'] = $this->data;
        }

        return $result;
    }
}

class DNSCache {
    private int $maxSize;
    private array $cache = [];
    private int $size = 0;

    public function __construct(int $maxSize = 1024) {
        $this->maxSize = $maxSize;
    }

    public function get(string $key): ?array {
        if (!isset($this->cache[$key])) {
            return null;
        }

        $entry = $this->cache[$key];
        $timestamp = $entry['timestamp'];
        $records = $entry['records'];

        $validRecords = [];
        $currentTime = microtime(true);

        foreach ($records as $record) {
            $elapsed = $currentTime - $timestamp;
            if ($record->ttl > $elapsed) {
                $remainingTTL = $record->ttl - (int)$elapsed;
                $cachedRecord = new DNSRecord(
                    $record->name,
                    $record->type,
                    $record->ttl,
                    $record->data,
                    $record->section,
                    $record->preference,
                    $record->rdata,
                    $timestamp
                );
                $validRecords[] = $cachedRecord;
            }
        }

        if (!empty($validRecords)) {
            $this->cache[$key]['access_time'] = microtime(true);
            return $validRecords;
        } else {
            unset($this->cache[$key]);
            $this->size--;
            return null;
        }
    }

    public function put(string $key, array $records): void {
        if (isset($this->cache[$key])) {
            unset($this->cache[$key]);
        } else {
            $this->size++;
        }

        $this->cache[$key] = [
            'timestamp' => microtime(true),
            'access_time' => microtime(true),
            'records' => $records
        ];

        if ($this->size > $this->maxSize) {
            $this->evictOldest();
        }
    }

    private function evictOldest(): void {
        $oldestKey = null;
        $oldestTime = PHP_FLOAT_MAX;

        foreach ($this->cache as $key => $entry) {
            if ($entry['access_time'] < $oldestTime) {
                $oldestTime = $entry['access_time'];
                $oldestKey = $key;
            }
        }

        if ($oldestKey !== null) {
            unset($this->cache[$oldestKey]);
            $this->size--;
        }
    }

    public function clear(): void {
        $this->cache = [];
        $this->size = 0;
    }

    public function size(): int {
        return $this->size;
    }
}

class DNSResolver {
    const DEFAULT_DNS_SERVERS = [
        ['8.8.8.8', 53],
        ['1.1.1.1', 53],
        ['9.9.9.9', 53],
        ['208.67.222.222', 53]
    ];
    const MAX_UDP_SIZE = 4096;
    const MAX_CNAME_REDIRECTS = 15;
    const DEFAULT_TIMEOUT = 3;
    const DEFAULT_RETRIES = 3;

    private array $dnsServers;
    private int $timeout;
    private int $retries;
    private bool $useTcp;
    private bool $requestDnssec;
    private bool $enableCache;
    private DNSCache $cache;
    private array $queryStats = [];

    public function __construct(
        array $dnsServers = null,
        int $timeout = self::DEFAULT_TIMEOUT,
        int $retries = self::DEFAULT_RETRIES,
        bool $useTcp = false,
        bool $requestDnssec = false,
        bool $enableCache = true,
        int $maxCacheSize = 1024
    ) {
        $this->dnsServers = $dnsServers ?? self::DEFAULT_DNS_SERVERS;
        $this->timeout = $timeout;
        $this->retries = $retries;
        $this->useTcp = $useTcp;
        $this->requestDnssec = $requestDnssec;
        $this->enableCache = $enableCache;
        $this->cache = new DNSCache($maxCacheSize);
        $this->validateDnsServers();
    }

    private function validateDnsServers(): void {
        foreach ($this->dnsServers as $server) {
            if (!is_array($server) || count($server) !== 2) {
                throw new InvalidArgumentException("Invalid DNS server format");
            }
            
            $ip = $server[0];
            $port = $server[1];
            
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new InvalidArgumentException("Invalid IP address: $ip");
            }
            
            if ($port < 1 || $port > 65535) {
                throw new InvalidArgumentException("Invalid port number: $port");
            }
        }
    }

    private function isValidDomain(string $domain): bool {
        if ($domain === '.') {
            return true;
        }
        
        $domain = rtrim($domain, '.');
        
        if (empty($domain) || strlen($domain) > 253) {
            return false;
        }
        
        if (!preg_match('/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i', $domain)) {
            return false;
        }
        
        return true;
    }

    private function buildQuery(string $domain, int $queryType, bool $dnssec = false): array {
        if ($domain !== '.' && !$this->isValidDomain($domain)) {
            throw new InvalidArgumentException("Invalid domain name: $domain");
        }

        $tid = random_int(0, 65535);
        $flags = 0x0100;
        $sourcePort = random_int(1024, 65535);

        $header = pack('n6', $tid, $flags, 1, 0, 0, 1);

        if ($domain === '.') {
            $qname = "\x00";
        } else {
            $qname = '';
            $labels = explode('.', $domain);
            foreach ($labels as $label) {
                $qname .= pack('C', strlen($label)) . $label;
            }
            $qname .= "\x00";
        }

        $question = $qname . pack('n2', $queryType, 1);

        $udpPayload = 4096;
        $ednsFlags = $dnssec ? 0x80000000 : 0;
        $edns = "\x00" . pack('nnNn', 41, $udpPayload, $ednsFlags, 0);

        return [$header . $question . $edns, $tid, $sourcePort];
    }

    private function parseName(string $data, int $offset, array &$seenPointers = []): array {
        if ($offset >= strlen($data)) {
            throw new RuntimeException("Offset beyond packet length");
        }

        $labels = [];
        $jumped = false;
        $originalOffset = $offset;
        $maxJumps = 20;
        $jumpCount = 0;

        while (true) {
            if (in_array($offset, $seenPointers)) {
                throw new RuntimeException("DNS compression loop detected");
            }
            $seenPointers[] = $offset;

            if ($offset >= strlen($data)) {
                throw new RuntimeException("DNS packet parsing overflow");
            }

            $length = ord($data[$offset]);
            if ($length === 0) {
                $offset++;
                break;
            }
            
            if (($length & 0xC0) === 0xC0) {
                if ($offset + 1 >= strlen($data)) {
                    throw new RuntimeException("Invalid DNS pointer offset");
                }
                $pointer = unpack('n', substr($data, $offset, 2))[1] & 0x3FFF;
                if ($pointer >= strlen($data)) {
                    throw new RuntimeException("DNS pointer out of bounds");
                }
                if (!$jumped) {
                    $originalOffset = $offset + 2;
                }
                $offset = $pointer;
                $jumped = true;
                $jumpCount++;
                if ($jumpCount >= $maxJumps) {
                    throw new RuntimeException("Too many DNS pointer jumps");
                }
                continue;
            } else {
                $offset++;
                if ($offset + $length > strlen($data)) {
                    throw new RuntimeException("DNS label length exceeds packet size");
                }
                $label = substr($data, $offset, $length);
                $labels[] = $label;
                $offset += $length;
            }
        }

        return [implode('.', $labels), $jumped ? $originalOffset : $offset];
    }

    private function parseRecordData(int $rtype, string $rdata, string $packet, int $rdataStart) {
        try {
            switch ($rtype) {
                case DNSRecordType::A:
                    if (strlen($rdata) !== 4) {
                        return bin2hex($rdata);
                    }
                    return inet_ntop($rdata);
                    
                case DNSRecordType::AAAA:
                    if (strlen($rdata) !== 16) {
                        return bin2hex($rdata);
                    }
                    return inet_ntop($rdata);
                    
                case DNSRecordType::MX:
                    if (strlen($rdata) < 3) {
                        throw new RuntimeException("MX record too short");
                    }
                    $preference = unpack('n', substr($rdata, 0, 2))[1];
                    [$exchange] = $this->parseName($packet, $rdataStart + 2);
                    return [$exchange, $preference];
                    
                case DNSRecordType::SRV:
                    if (strlen($rdata) < 7) {
                        throw new RuntimeException("SRV record too short");
                    }
                    $unpacked = unpack('npriority/nweight/nport', substr($rdata, 0, 6));
                    [$target] = $this->parseName($packet, $rdataStart + 6);
                    return [
                        'priority' => $unpacked['priority'],
                        'weight' => $unpacked['weight'],
                        'port' => $unpacked['port'],
                        'target' => $target
                    ];
                    
                case DNSRecordType::CNAME:
                case DNSRecordType::NS:
                case DNSRecordType::PTR:
                case DNSRecordType::DNAME:
                    [$name] = $this->parseName($packet, $rdataStart);
                    return $name;
                    
                case DNSRecordType::TXT:
                    $parts = [];
                    $pos = 0;
                    $len = strlen($rdata);
                    while ($pos < $len) {
                        if ($pos + 1 > $len) break;
                        $txtLen = ord($rdata[$pos]);
                        $pos++;
                        if ($pos + $txtLen > $len) break;
                        $parts[] = substr($rdata, $pos, $txtLen);
                        $pos += $txtLen;
                    }
                    return implode('', $parts);
                    
                case DNSRecordType::SOA:
                    $offset = $rdataStart;
                    [$mname, $offset] = $this->parseName($packet, $offset);
                    [$rname, $offset] = $this->parseName($packet, $offset);
                    if ($offset + 20 > strlen($packet)) {
                        throw new RuntimeException("SOA numeric fields truncated");
                    }
                    $items = unpack('N5', substr($packet, $offset, 20));
                    return [
                        'mname' => $mname,
                        'rname' => $rname,
                        'serial' => $items[1],
                        'refresh' => $items[2],
                        'retry' => $items[3],
                        'expire' => $items[4],
                        'minimum' => $items[5]
                    ];
                    
                default:
                    return bin2hex($rdata);
            }
        } catch (Exception $e) {
            error_log("Failed to parse record type {$rtype}: " . $e->getMessage());
            return bin2hex($rdata);
        }
    }

    private function parseResponse(string $data, int $tid): array {
        if (strlen($data) < 12) {
            throw new RuntimeException("DNS response too short");
        }

        $header = unpack('ntid/nflags/nqdcount/nancount/nnscount/narcount', substr($data, 0, 12));
        
        if ($header['tid'] !== $tid) {
            throw new RuntimeException("Transaction ID mismatch");
        }
        
        if (($header['flags'] >> 15) !== 1) {
            throw new RuntimeException("Not a DNS response");
        }

        $totalRRs = $header['qdcount'] + $header['ancount'] + $header['nscount'] + $header['arcount'];
        if ($totalRRs > 1000) {
            throw new RuntimeException("Excessive RR count: {$totalRRs}");
        }

        $rcode = $header['flags'] & 0xF;
        if ($rcode !== 0) {
            $errorCodes = [
                0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN",
                4 => "NOTIMP", 5 => "REFUSED", 6 => "YXDOMAIN", 7 => "YXRRSET",
                8 => "NXRRSET", 9 => "NOTAUTH", 10 => "NOTZONE"
            ];
            throw new RuntimeException("DNS error: " . ($errorCodes[$rcode] ?? "RCODE_{$rcode}"));
        }

        $truncated = ($header['flags'] >> 9) & 0x1;
        if ($truncated && !$this->useTcp) {
            error_log("Response truncated (TC=1), consider using TCP");
        }

        $records = [];
        $offset = 12;

        for ($i = 0; $i < $header['qdcount']; $i++) {
            [, $offset] = $this->parseName($data, $offset);
            if ($offset + 4 > strlen($data)) {
                throw new RuntimeException("Question section truncated");
            }
            $offset += 4;
        }

        $sections = [
            'answer' => $header['ancount'],
            'authority' => $header['nscount'],
            'additional' => $header['arcount']
        ];

        foreach ($sections as $section => $count) {
            for ($i = 0; $i < $count; $i++) {
                [$name, $offset] = $this->parseName($data, $offset);
                if ($offset + 10 > strlen($data)) {
                    throw new RuntimeException("RR header exceeds packet size");
                }
                $rrHeader = unpack('ntype/nclass/Nttl/nrdlength', substr($data, $offset, 10));
                $offset += 10;
                
                if ($offset + $rrHeader['rdlength'] > strlen($data)) {
                    throw new RuntimeException("RR data exceeds packet size");
                }
                
                $rdata = substr($data, $offset, $rrHeader['rdlength']);
                $rdataStart = $offset;
                $offset += $rrHeader['rdlength'];

                if ($rrHeader['class'] !== 1) {
                    continue;
                }

                try {
                    $parsedData = $this->parseRecordData($rrHeader['type'], $rdata, $data, $rdataStart);
                    
                    if ($rrHeader['type'] === DNSRecordType::MX && is_array($parsedData)) {
                        [$exchange, $preference] = $parsedData;
                        $records[] = new DNSRecord(
                            $name,
                            $rrHeader['type'],
                            $rrHeader['ttl'],
                            $exchange,
                            $section,
                            $preference,
                            $rdata
                        );
                    } elseif ($rrHeader['type'] === DNSRecordType::SRV && is_array($parsedData)) {
                        $records[] = new DNSRecord(
                            $name,
                            $rrHeader['type'],
                            $rrHeader['ttl'],
                            $parsedData,
                            $section,
                            null,
                            $rdata
                        );
                    } else {
                        $records[] = new DNSRecord(
                            $name,
                            $rrHeader['type'],
                            $rrHeader['ttl'],
                            $parsedData,
                            $section,
                            null,
                            $rdata
                        );
                    }
                } catch (Exception $e) {
                    $records[] = new DNSRecord(
                        $name,
                        DNSRecordType::ANY,
                        $rrHeader['ttl'],
                        bin2hex($rdata),
                        $section,
                        null,
                        $rdata
                    );
                }
            }
        }

        return $records;
    }

    private function sendQuery(string $query, array $server, ?int $sourcePort = null): string {
        $ip = $server[0];
        $port = $server[1];

        if ($this->useTcp) {
            $socket = @fsockopen("tcp://{$ip}", $port, $errno, $errstr, $this->timeout);
            if (!$socket) {
                throw new RuntimeException("TCP connection failed: {$errstr}");
            }
            
            stream_set_timeout($socket, $this->timeout);
            $length = pack('n', strlen($query));
            fwrite($socket, $length . $query);
            
            $response = '';
            while (!feof($socket)) {
                $response .= fread($socket, 4096);
            }
            fclose($socket);
            
            if (strlen($response) < 2) {
                throw new RuntimeException("Invalid TCP response");
            }
            
            $responseLength = unpack('n', substr($response, 0, 2))[1];
            return substr($response, 2, $responseLength);
        } else {
            $socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
            if (!$socket) {
                throw new RuntimeException("UDP socket creation failed");
            }
            
            socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $this->timeout, 'usec' => 0]);
            
            if ($sourcePort) {
                if (!@socket_bind($socket, '0.0.0.0', $sourcePort)) {
                    error_log("Failed to bind to source port {$sourcePort}");
                }
            }
            
            if (!@socket_connect($socket, $ip, $port)) {
                socket_close($socket);
                throw new RuntimeException("UDP connection failed");
            }
            
            if (!@socket_send($socket, $query, strlen($query), 0)) {
                socket_close($socket);
                throw new RuntimeException("UDP send failed");
            }
            
            $response = '';
            $from = '';
            $portFrom = 0;
            
            $bytes = @socket_recvfrom($socket, $response, self::MAX_UDP_SIZE, 0, $from, $portFrom);
            socket_close($socket);
            
            if ($bytes === false) {
                throw new RuntimeException("UDP receive failed");
            }
            
            if ($from !== $ip) {
                throw new RuntimeException("Response from unexpected source {$from} (expected {$ip})");
            }
            
            return $response;
        }
    }

    private function getCacheKey(string $domain, int $queryType, array $server): string {
        $keyData = "{$domain}:{$queryType}:{$server[0]}:{$server[1]}";
        return md5($keyData);
    }

    public function resolve(
        string $domain,
        $queryType = DNSRecordType::A,
        ?array $server = null,
        bool $followCnames = true,
        int $cnameDepth = 0
    ): array {
        if ($cnameDepth > self::MAX_CNAME_REDIRECTS) {
            throw new RuntimeException("Too many CNAME redirects (max " . self::MAX_CNAME_REDIRECTS . ")");
        }
        
        $domain = rtrim($domain, '.');
        
        if ($domain !== '.' && !$this->isValidDomain($domain)) {
            throw new InvalidArgumentException("Invalid domain format: {$domain}");
        }

        if (is_array($queryType)) {
            $results = [];
            foreach ($queryType as $qt) {
                try {
                    $results = array_merge($results, $this->resolve($domain, $qt, $server, $followCnames, $cnameDepth));
                } catch (Exception $e) {
                    error_log("Failed to resolve {$qt} for {$domain}: " . $e->getMessage());
                }
            }
            return $results;
        }

        if (is_string($queryType)) {
            $queryType = strtoupper($queryType);
            $typeConst = 'DNSRecordType::' . $queryType;
            if (!defined($typeConst)) {
                throw new InvalidArgumentException("Unsupported query type: {$queryType}");
            }
            $queryType = constant($typeConst);
        }

        $servers = $server ? [$server] : $this->dnsServers;
        
        $cacheKey = null;
        if ($this->enableCache && $server) {
            $cacheKey = $this->getCacheKey($domain, $queryType, $server);
            $cached = $this->cache->get($cacheKey);
            if ($cached !== null) {
                error_log("Cache hit for {$domain} (" . DNSRecordType::getName($queryType) . ")");
                return $cached;
            }
        }

        $lastErrors = [];

        for ($attempt = 0; $attempt < $this->retries; $attempt++) {
            foreach ($servers as $currentServer) {
                try {
                    $serverKey = $currentServer[0] . ':' . $currentServer[1];
                    $this->queryStats[$serverKey] = ($this->queryStats[$serverKey] ?? 0) + 1;
                    
                    [$query, $tid, $sourcePort] = $this->buildQuery($domain, $queryType, $this->requestDnssec);
                    $startTime = microtime(true);

                    $data = $this->sendQuery($query, $currentServer, $sourcePort);
                    if (empty($data)) {
                        throw new RuntimeException("Empty response from DNS server");
                    }

                    $records = $this->parseResponse($data, $tid);
                    if (empty($records)) {
                        throw new RuntimeException("No records in response");
                    }

                    if ($queryType === DNSRecordType::ANY) {
                        $finalRecords = $records;
                    } else {
                        $targetRecords = array_filter($records, fn($r) => $r->type === $queryType && $r->section === 'answer');
                        $cnameRecords = array_filter($records, fn($r) => $r->type === DNSRecordType::CNAME && $r->section === 'answer');
                        
                        if (!empty($targetRecords)) {
                            $finalRecords = array_values($targetRecords);
                        } elseif ($followCnames && !empty($cnameRecords)) {
                            $cnameTarget = reset($cnameRecords)->data;
                            error_log("Following CNAME {$domain} -> {$cnameTarget}");
                            $finalRecords = $this->resolve($cnameTarget, $queryType, 
                                $server ?? $currentServer, true, $cnameDepth + 1);
                        } else {
                            $finalRecords = [];
                        }
                    }

                    if (!empty($finalRecords)) {
                        $elapsed = (microtime(true) - $startTime) * 1000;
                        error_log("Resolved {$domain} (" . DNSRecordType::getName($queryType) . 
                                ") via {$currentServer[0]} in {$elapsed}ms");
                        
                        if ($cacheKey) {
                            $this->cache->put($cacheKey, $finalRecords);
                        }
                        
                        return $finalRecords;
                    }

                } catch (Exception $e) {
                    $errorMsg = "{$currentServer[0]}: " . get_class($e) . ": " . $e->getMessage();
                    $lastErrors[] = $errorMsg;
                    error_log("Attempt " . ($attempt + 1) . " failed: {$errorMsg}");
                    
                    if ($attempt < $this->retries - 1) {
                        sleep(min(2 ** $attempt, 10));
                    }
                }
            }
        }

        throw new RuntimeException("All {$this->retries} attempts failed. Errors: " . implode(', ', $lastErrors));
    }

    public function query(
        string $domain,
        $queryType = "A",
        ?array $server = null,
        bool $verbose = false,
        bool $jsonOutput = false,
        bool $followCnames = true
    ): void {
        try {
            $records = $this->resolve($domain, $queryType, $server, $followCnames);

            if ($jsonOutput) {
                if (is_array($queryType)) {
                    $qtypeStr = array_map(fn($qt) => is_string($qt) ? $qt : DNSRecordType::getName($qt), $queryType);
                } else {
                    $qtypeStr = is_string($queryType) ? $queryType : DNSRecordType::getName($queryType);
                }
                
                $result = [
                    'domain' => $domain,
                    'query_type' => $qtypeStr,
                    'records' => array_map(fn($r) => $r->toArray(), $records)
                ];
                
                echo json_encode($result, JSON_PRETTY_PRINT) . "\n";
                return;
            }

            if (is_array($queryType)) {
                $typeStr = implode(',', array_map(fn($t) => is_string($t) ? $t : DNSRecordType::getName($t), $queryType));
            } else {
                $typeStr = is_string($queryType) ? $queryType : DNSRecordType::getName($queryType);
            }

            echo "\nDNS {$typeStr} records for {$domain}:\n";
            
            $sections = [];
            foreach ($records as $r) {
                $sections[$r->section][] = $r;
            }
            
            foreach (['answer', 'authority', 'additional'] as $secName) {
                if (!empty($sections[$secName])) {
                    echo "\n;; " . ucfirst($secName) . " Section:\n";
                    foreach ($sections[$secName] as $rec) {
                        if ($verbose) {
                            echo "{$rec->name}\t{$rec}\n";
                        } else {
                            echo "{$rec}\n";
                        }
                    }
                }
            }
            echo "\n";
        } catch (Exception $e) {
            echo "\nError resolving {$domain}: {$e->getMessage()}\n";
        }
    }

    public function getStats(): array {
        return $this->queryStats;
    }

    public function clearCache(): void {
        $this->cache->clear();
    }
}

function validateServerString(string $serverStr): array {
    if (str_starts_with($serverStr, '[')) {
        $bracketEnd = strpos($serverStr, ']');
        if ($bracketEnd === false) {
            throw new InvalidArgumentException("Invalid IPv6 address format: {$serverStr}");
        }
        
        $ip = substr($serverStr, 1, $bracketEnd - 1);
        $rest = substr($serverStr, $bracketEnd + 1);
        
        if (str_starts_with($rest, ':')) {
            $port = substr($rest, 1);
            $port = $port === '' ? 53 : (int)$port;
        } else {
            if ($rest !== '') {
                throw new InvalidArgumentException("Invalid IPv6 address format: {$serverStr}");
            }
            $port = 53;
        }
    } else {
        $parts = explode(':', $serverStr);
        if (count($parts) === 2) {
            if (!filter_var($parts[0], FILTER_VALIDATE_IP)) {
                throw new InvalidArgumentException("IPv6 addresses must be in brackets: {$serverStr}");
            }
            $ip = $parts[0];
            $port = (int)$parts[1];
        } elseif (count($parts) === 1) {
            $ip = $parts[0];
            $port = 53;
        } else {
            if (!filter_var($serverStr, FILTER_VALIDATE_IP)) {
                throw new InvalidArgumentException("Invalid server format: {$serverStr}");
            }
            $ip = $serverStr;
            $port = 53;
        }
    }
    
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        throw new InvalidArgumentException("Invalid IP address: {$ip}");
    }
    
    if ($port < 1 || $port > 65535) {
        throw new InvalidArgumentException("Invalid port number: {$port}");
    }
    
    return [$ip, $port];
}

if (PHP_SAPI === 'cli') {
    $shortopts = "t:s:v";
    $longopts = [
        "type:",
        "server:",
        "tcp",
        "request-dnssec",
        "dnssec",
        "no-follow-cnames",
        "verbose",
        "json",
        "debug",
        "ipv6-only",
        "ipv4-only",
        "no-cache",
        "help"
    ];
    
    $options = getopt($shortopts, $longopts);
    
    if (isset($options['help']) || $argc < 2) {
        echo "Usage: php dns_resolver.php <domain> [options]\n";
        echo "Options:\n";
        echo "  -t, --type <type>          DNS record type (A, AAAA, MX, etc.) or comma-separated list\n";
        echo "  -s, --server <ip:port>     Specific DNS server\n";
        echo "  --tcp                      Use TCP instead of UDP\n";
        echo "  --request-dnssec, --dnssec Request DNSSEC records\n";
        echo "  --no-follow-cnames         Disable following CNAME records\n";
        echo "  -v, --verbose              Verbose output\n";
        echo "  --json                     Output in JSON format\n";
        echo "  --debug                    Enable debug logging\n";
        echo "  --ipv6-only                Use only IPv6 DNS servers\n";
        echo "  --ipv4-only                Use only IPv4 DNS servers\n";
        echo "  --no-cache                 Disable response caching\n";
        echo "  --help                     Show this help\n";
        exit(0);
    }
    
    $domain = $argv[1];
    $queryType = $options['type'] ?? ($options['t'] ?? 'A');
    $server = $options['server'] ?? ($options['s'] ?? null);
    $useTcp = isset($options['tcp']);
    $requestDnssec = isset($options['request-dnssec']) || isset($options['dnssec']);
    $noFollowCnames = isset($options['no-follow-cnames']);
    $verbose = isset($options['verbose']) || isset($options['v']);
    $jsonOutput = isset($options['json']);
    $debug = isset($options['debug']);
    $ipv6Only = isset($options['ipv6-only']);
    $ipv4Only = isset($options['ipv4-only']);
    $noCache = isset($options['no-cache']);
    
    if ($debug) {
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    }
    
    try {
        $serverConfig = null;
        if ($server) {
            $serverConfig = validateServerString($server);
        }
        
        $queryTypes = str_contains($queryType, ',') ? explode(',', $queryType) : $queryType;
        
        $resolver = new DNSResolver(
            useTcp: $useTcp,
            requestDnssec: $requestDnssec,
            enableCache: !$noCache
        );
        
        $resolver->query(
            $domain,
            queryType: $queryTypes,
            server: $serverConfig,
            verbose: $verbose,
            jsonOutput: $jsonOutput,
            followCnames: !$noFollowCnames
        );
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}
