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
        return $map[$type] ?? 'TYPE' . $type;
    }
    
    public static function getTypeFromName(string $name): ?int {
        $map = [
            'A' => self::A,
            'NS' => self::NS,
            'CNAME' => self::CNAME,
            'SOA' => self::SOA,
            'PTR' => self::PTR,
            'MX' => self::MX,
            'TXT' => self::TXT,
            'AAAA' => self::AAAA,
            'SRV' => self::SRV,
            'DNAME' => self::DNAME,
            'DS' => self::DS,
            'RRSIG' => self::RRSIG,
            'NSEC' => self::NSEC,
            'DNSKEY' => self::DNSKEY,
            'HTTPS' => self::HTTPS,
            'ANY' => self::ANY
        ];
        return $map[strtoupper($name)] ?? null;
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
        return max(0, min($this->ttl, $remaining));
    }

    public function __toString(): string {
        $typeStr = DNSRecordType::getName($this->type);
        $ttlDisplay = $this->cacheTime ? $this->getRemainingTTL() : $this->ttl;

        switch ($this->type) {
            case DNSRecordType::MX:
                return sprintf("%s\t%d\t%d\t%s", $typeStr, $ttlDisplay, $this->preference, $this->data);
            case DNSRecordType::SOA:
                $soa = $this->data;
                if (is_array($soa)) {
                    return sprintf("%s\t%d\t%s %s (%d %d %d %d %d)", 
                        $typeStr, $ttlDisplay, 
                        $soa['mname'], $soa['rname'],
                        $soa['serial'], $soa['refresh'], $soa['retry'],
                        $soa['expire'], $soa['minimum']);
                }
                return sprintf("%s\t%d\t%s", $typeStr, $ttlDisplay, $this->data);
            case DNSRecordType::TXT:
                return sprintf("%s\t%d\t\"%s\"", $typeStr, $ttlDisplay, $this->data);
            case DNSRecordType::SRV:
                $srv = $this->data;
                if (is_array($srv)) {
                    return sprintf("%s\t%d\t%d %d %d %s", 
                        $typeStr, $ttlDisplay,
                        $srv['priority'], $srv['weight'], $srv['port'], $srv['target']);
                }
                return sprintf("%s\t%d\t%s", $typeStr, $ttlDisplay, $this->data);
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
                if (is_array($this->data)) {
                    $result = array_merge($result, $this->data);
                } else {
                    $result['data'] = $this->data;
                }
                break;
            case DNSRecordType::SRV:
                if (is_array($this->data)) {
                    $result = array_merge($result, $this->data);
                } else {
                    $result['data'] = $this->data;
                }
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
    private const MAX_RECORDS_PER_KEY = 100;

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
            if (!($record instanceof DNSRecord)) {
                continue;
            }
            $elapsed = $currentTime - $timestamp;
            if ($record->ttl > $elapsed) {
                $cachedRecord = clone $record;
                $cachedRecord->cacheTime = $timestamp;
                $validRecords[] = $cachedRecord;
            }
        }

        if (!empty($validRecords)) {
            $this->cache[$key]['access_time'] = microtime(true);
            $this->cache[$key]['hits'] = ($this->cache[$key]['hits'] ?? 0) + 1;
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
            $this->size--;
        }

        if (count($records) > self::MAX_RECORDS_PER_KEY) {
            $records = array_slice($records, 0, self::MAX_RECORDS_PER_KEY);
        }

        $this->cache[$key] = [
            'timestamp' => microtime(true),
            'access_time' => microtime(true),
            'records' => $records,
            'hits' => 0
        ];
        $this->size++;

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

    public function getStats(): array {
        $stats = [
            'size' => $this->size,
            'max_size' => $this->maxSize,
            'hits' => 0,
            'entries' => []
        ];
        
        foreach ($this->cache as $key => $entry) {
            $stats['hits'] += $entry['hits'] ?? 0;
            $stats['entries'][] = [
                'key' => $key,
                'hits' => $entry['hits'] ?? 0,
                'age' => microtime(true) - $entry['timestamp'],
                'record_count' => count($entry['records'])
            ];
        }
        
        return $stats;
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
    const MAX_RESPONSE_SIZE = 65535;
    const MAX_RECORDS_PER_RESPONSE = 1000;
    const RATE_LIMIT_WINDOW = 60;
    const MAX_QUERIES_PER_WINDOW = 100;

    private array $dnsServers;
    private int $timeout;
    private int $retries;
    private bool $defaultUseTcp;
    private bool $requestDnssec;
    private bool $enableCache;
    private DNSCache $cache;
    private array $queryStats = [];
    private bool $debug;
    private ?string $ipFamily;
    private array $rateLimits = [];

    public function __construct(
        array $dnsServers = null,
        int $timeout = self::DEFAULT_TIMEOUT,
        int $retries = self::DEFAULT_RETRIES,
        bool $useTcp = false,
        bool $requestDnssec = false,
        bool $enableCache = true,
        int $maxCacheSize = 1024,
        bool $debug = false,
        ?string $ipFamily = null
    ) {
        $this->dnsServers = $dnsServers ?? self::DEFAULT_DNS_SERVERS;
        $this->timeout = $timeout;
        $this->retries = $retries;
        $this->defaultUseTcp = $useTcp;
        $this->requestDnssec = $requestDnssec;
        $this->enableCache = $enableCache;
        $this->debug = $debug;
        $this->ipFamily = $ipFamily;
        $this->cache = new DNSCache($maxCacheSize);
        
        if ($ipFamily) {
            $this->dnsServers = array_filter($this->dnsServers, function($server) use ($ipFamily) {
                $isIPv6 = str_contains($server[0], ':');
                return ($ipFamily === 'ipv4' && !$isIPv6) || ($ipFamily === 'ipv6' && $isIPv6);
            });
            
            if (empty($this->dnsServers)) {
                throw new InvalidArgumentException("No {$ipFamily} DNS servers available");
            }
        }
        
        $this->validateDnsServers();
    }

    private function validateDnsServers(): void {
        if (empty($this->dnsServers)) {
            throw new InvalidArgumentException("No DNS servers provided");
        }
        
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

    private function checkRateLimit(string $server): void {
        $now = time();
        if (!isset($this->rateLimits[$server])) {
            $this->rateLimits[$server] = [];
        }
        
        $this->rateLimits[$server] = array_filter(
            $this->rateLimits[$server],
            fn($t) => $t > $now - self::RATE_LIMIT_WINDOW
        );
        
        if (count($this->rateLimits[$server]) >= self::MAX_QUERIES_PER_WINDOW) {
            throw new RuntimeException("Rate limit exceeded for server {$server}");
        }
        
        $this->rateLimits[$server][] = $now;
    }

    private function isValidDomain(string $domain): bool {
        if ($domain === '.' || $domain === '') {
            return true;
        }
        
        $domain = rtrim($domain, '.');
        
        if (empty($domain) || strlen($domain) > 253) {
            return false;
        }
        
        $labels = explode('.', $domain);
        if (count($labels) > 127) {
            return false;
        }
        
        foreach ($labels as $label) {
            if (strlen($label) > 63) {
                return false;
            }
            if (!preg_match('/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i', $label)) {
                return false;
            }
        }
        
        return true;
    }

    private function buildQuery(string $domain, int $queryType): array {
        if ($domain !== '.' && $domain !== '' && !$this->isValidDomain($domain)) {
            throw new InvalidArgumentException("Invalid domain name: $domain");
        }

        $tid = random_int(0, 65535);
        $flags = 0x0100;

        $additionalCount = 0;
        $additionalSection = '';

        if ($this->requestDnssec) {
            $ednsUdpSize = self::MAX_UDP_SIZE;
            $extRcode = 0;
            $ednsVersion = 0;
            $ednsFlags = 0x8000;

            $optRecord = "\x00";
            $optRecord .= pack('n', 41);
            $optRecord .= pack('n', $ednsUdpSize);
            $optRecord .= pack('C', $extRcode);
            $optRecord .= pack('C', $ednsVersion);
            $optRecord .= pack('n', $ednsFlags);
            $optRecord .= pack('n', 0);

            $additionalSection = $optRecord;
            $additionalCount = 1;
        }

        $header = pack('n6', $tid, $flags, 1, 0, 0, $additionalCount);

        if ($domain === '.' || $domain === '') {
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

        return [$header . $question . $additionalSection, $tid];
    }

    private function parseName(string $data, int $offset, array &$seenPointers = [], ?int $streamEnd = null): array {
        $packetLength = strlen($data);
        if ($offset < 0 || $offset >= $packetLength) {
            throw new RuntimeException("Offset beyond packet length");
        }

        if ($streamEnd !== null && ($streamEnd < $offset || $streamEnd > $packetLength)) {
            throw new RuntimeException("Invalid DNS name boundary");
        }

        $labels = [];
        $jumped = false;
        $nextOffset = $offset;
        $maxJumps = 20;
        $jumpCount = 0;

        while (true) {
            if ($jumpCount > $maxJumps) {
                throw new RuntimeException("Too many DNS pointer jumps");
            }

            if (isset($seenPointers[$offset])) {
                throw new RuntimeException("DNS compression loop detected");
            }
            $seenPointers[$offset] = true;

            if ($offset >= $packetLength) {
                throw new RuntimeException("DNS packet parsing overflow");
            }

            if (!$jumped && $streamEnd !== null && $offset >= $streamEnd) {
                throw new RuntimeException("DNS name exceeds RDATA boundary");
            }

            $length = ord($data[$offset]);

            if ($length === 0) {
                if (!$jumped) {
                    $nextOffset = $offset + 1;
                    if ($streamEnd !== null && $nextOffset > $streamEnd) {
                        throw new RuntimeException("DNS name exceeds RDATA boundary");
                    }
                }
                break;
            }

            if (($length & 0xC0) === 0xC0) {
                if ($offset + 1 >= $packetLength) {
                    throw new RuntimeException("Invalid DNS pointer offset");
                }

                if (!$jumped && $streamEnd !== null && $offset + 2 > $streamEnd) {
                    throw new RuntimeException("DNS pointer exceeds RDATA boundary");
                }

                $pointerData = unpack('n', substr($data, $offset, 2));
                if ($pointerData === false) {
                    throw new RuntimeException("Failed to unpack DNS pointer");
                }

                $pointer = $pointerData[1] & 0x3FFF;
                if ($pointer >= $packetLength) {
                    throw new RuntimeException("DNS pointer out of bounds");
                }

                if (!$jumped) {
                    $nextOffset = $offset + 2;
                }

                $offset = $pointer;
                $jumped = true;
                $jumpCount++;
                continue;
            }

            if (($length & 0xC0) !== 0) {
                throw new RuntimeException(sprintf("Invalid DNS label type: 0x%02x", $length));
            }

            if ($length > 63) {
                throw new RuntimeException("Invalid label length: $length");
            }

            $offset++;
            if ($offset + $length > $packetLength) {
                throw new RuntimeException("DNS label length exceeds packet size");
            }

            if (!$jumped && $streamEnd !== null && $offset + $length > $streamEnd) {
                throw new RuntimeException("DNS label exceeds RDATA boundary");
            }

            $labels[] = substr($data, $offset, $length);
            $offset += $length;

            if (!$jumped) {
                $nextOffset = $offset;
            }
        }

        $name = implode('.', $labels);
        return [$name === '' ? '.' : $name, $nextOffset];
    }

    private function parseRecordData(int $rtype, string $rdata, string $packet, int $rdataStart) {
        $rdataLength = strlen($rdata);
        $rdataEnd = $rdataStart + $rdataLength;

        switch ($rtype) {
            case DNSRecordType::A:
                if ($rdataLength !== 4) {
                    throw new RuntimeException("Invalid A record length: {$rdataLength}");
                }
                $ip = inet_ntop($rdata);
                if ($ip === false) {
                    throw new RuntimeException("Failed to parse A record");
                }
                return $ip;

            case DNSRecordType::AAAA:
                if ($rdataLength !== 16) {
                    throw new RuntimeException("Invalid AAAA record length: {$rdataLength}");
                }
                $ip = inet_ntop($rdata);
                if ($ip === false) {
                    throw new RuntimeException("Failed to parse AAAA record");
                }
                return $ip;

            case DNSRecordType::MX:
                if ($rdataLength < 3) {
                    throw new RuntimeException("MX record too short");
                }
                $preferenceData = unpack('n', substr($rdata, 0, 2));
                if ($preferenceData === false) {
                    throw new RuntimeException("Failed to unpack MX preference");
                }
                $seenPointers = [];
                [$exchange, $nextOffset] = $this->parseName($packet, $rdataStart + 2, $seenPointers, $rdataEnd);
                if ($nextOffset !== $rdataEnd) {
                    throw new RuntimeException("MX record contains trailing data");
                }
                return [
                    'exchange' => $exchange,
                    'preference' => $preferenceData[1]
                ];

            case DNSRecordType::SRV:
                if ($rdataLength < 7) {
                    throw new RuntimeException("SRV record too short");
                }
                $fixed = unpack('npriority/nweight/nport', substr($rdata, 0, 6));
                if ($fixed === false) {
                    throw new RuntimeException("Failed to unpack SRV record");
                }
                $seenPointers = [];
                [$target, $nextOffset] = $this->parseName($packet, $rdataStart + 6, $seenPointers, $rdataEnd);
                if ($nextOffset !== $rdataEnd) {
                    throw new RuntimeException("SRV record contains trailing data");
                }
                return [
                    'priority' => $fixed['priority'],
                    'weight' => $fixed['weight'],
                    'port' => $fixed['port'],
                    'target' => $target
                ];

            case DNSRecordType::CNAME:
            case DNSRecordType::NS:
            case DNSRecordType::PTR:
            case DNSRecordType::DNAME:
                $seenPointers = [];
                [$name, $nextOffset] = $this->parseName($packet, $rdataStart, $seenPointers, $rdataEnd);
                if ($nextOffset !== $rdataEnd) {
                    throw new RuntimeException("Domain-name RDATA contains trailing data");
                }
                return $name;

            case DNSRecordType::TXT:
                $parts = [];
                $pos = 0;
                while ($pos < $rdataLength) {
                    $txtLen = ord($rdata[$pos]);
                    $pos++;
                    if ($pos + $txtLen > $rdataLength) {
                        throw new RuntimeException("TXT string exceeds RDATA boundary");
                    }
                    $parts[] = substr($rdata, $pos, $txtLen);
                    $pos += $txtLen;
                }
                return implode('', $parts);

            case DNSRecordType::SOA:
                $offset = $rdataStart;
                $seenPointers = [];
                [$mname, $offset] = $this->parseName($packet, $offset, $seenPointers, $rdataEnd);
                $seenPointers = [];
                [$rname, $offset] = $this->parseName($packet, $offset, $seenPointers, $rdataEnd);

                if ($offset + 20 !== $rdataEnd) {
                    throw new RuntimeException("Invalid SOA numeric field length");
                }

                $items = unpack('Nserial/Nrefresh/Nretry/Nexpire/Nminimum', substr($packet, $offset, 20));
                if ($items === false) {
                    throw new RuntimeException("Failed to unpack SOA record");
                }

                return [
                    'mname' => $mname,
                    'rname' => $rname,
                    'serial' => $items['serial'],
                    'refresh' => $items['refresh'],
                    'retry' => $items['retry'],
                    'expire' => $items['expire'],
                    'minimum' => $items['minimum']
                ];

            default:
                return bin2hex($rdata);
        }
    }

    private function parseResponse(string $data, int $tid, string $expectedDomain, int $expectedType): array {
        $packetLength = strlen($data);

        if ($packetLength < 12) {
            throw new RuntimeException("DNS response too short");
        }

        if ($packetLength > self::MAX_RESPONSE_SIZE) {
            throw new RuntimeException("DNS response too large");
        }

        $header = unpack('ntid/nflags/nqdcount/nancount/nnscount/narcount', substr($data, 0, 12));
        if ($header === false) {
            throw new RuntimeException("Failed to unpack DNS header");
        }

        if ($header['tid'] !== $tid) {
            throw new RuntimeException("Transaction ID mismatch");
        }

        if ((($header['flags'] >> 15) & 1) !== 1) {
            throw new RuntimeException("Not a DNS response");
        }

        if ((($header['flags'] >> 9) & 1) === 1) {
            throw new TruncatedResponseException("Response truncated (TC=1), retry with TCP");
        }

        if ($header['qdcount'] !== 1) {
            throw new RuntimeException("Unexpected question count: {$header['qdcount']}");
        }

        $totalRRs = $header['ancount'] + $header['nscount'] + $header['arcount'];
        if ($totalRRs > self::MAX_RECORDS_PER_RESPONSE) {
            throw new RuntimeException("Excessive RR count: {$totalRRs}");
        }

        $rcode = $header['flags'] & 0xF;
        if ($rcode !== 0) {
            $errorCodes = [
                0 => "NOERROR",
                1 => "FORMERR",
                2 => "SERVFAIL",
                3 => "NXDOMAIN",
                4 => "NOTIMP",
                5 => "REFUSED",
                6 => "YXDOMAIN",
                7 => "YXRRSET",
                8 => "NXRRSET",
                9 => "NOTAUTH",
                10 => "NOTZONE"
            ];
            $errorMsg = $errorCodes[$rcode] ?? "RCODE_{$rcode}";
            throw new RuntimeException("DNS error: {$errorMsg}");
        }

        $offset = 12;
        $seenPointers = [];
        [$questionName, $offset] = $this->parseName($data, $offset, $seenPointers);

        if ($offset + 4 > $packetLength) {
            throw new RuntimeException("Question section truncated");
        }

        $question = unpack('ntype/nclass', substr($data, $offset, 4));
        if ($question === false) {
            throw new RuntimeException("Failed to unpack DNS question");
        }
        $offset += 4;

        $normalizedExpected = $expectedDomain === '' || $expectedDomain === '.'
            ? '.'
            : strtolower(rtrim($expectedDomain, '.'));
        $normalizedQuestion = $questionName === '.'
            ? '.'
            : strtolower(rtrim($questionName, '.'));

        if ($normalizedQuestion !== $normalizedExpected) {
            throw new RuntimeException("Response question name mismatch");
        }

        if ($question['type'] !== $expectedType) {
            throw new RuntimeException("Response question type mismatch");
        }

        if ($question['class'] !== 1) {
            throw new RuntimeException("Response question class mismatch");
        }

        $records = [];
        $sections = [
            'answer' => $header['ancount'],
            'authority' => $header['nscount'],
            'additional' => $header['arcount']
        ];

        foreach ($sections as $section => $count) {
            for ($i = 0; $i < $count; $i++) {
                $seenPointers = [];
                [$name, $offset] = $this->parseName($data, $offset, $seenPointers);

                if ($offset + 10 > $packetLength) {
                    throw new RuntimeException("RR header exceeds packet size");
                }

                $rrHeader = unpack('ntype/nclass/Nttl/nrdlength', substr($data, $offset, 10));
                if ($rrHeader === false) {
                    throw new RuntimeException("Failed to unpack RR header");
                }
                $offset += 10;

                if ($offset + $rrHeader['rdlength'] > $packetLength) {
                    throw new RuntimeException("RR data exceeds packet size");
                }

                $rdataStart = $offset;
                $rdata = substr($data, $rdataStart, $rrHeader['rdlength']);
                $offset += $rrHeader['rdlength'];

                if ($rrHeader['type'] === 41) {
                    continue;
                }

                if ($rrHeader['class'] !== 1) {
                    continue;
                }

                $parsedData = $this->parseRecordData(
                    $rrHeader['type'],
                    $rdata,
                    $data,
                    $rdataStart
                );

                if ($rrHeader['type'] === DNSRecordType::MX && is_array($parsedData)) {
                    $records[] = new DNSRecord(
                        $name,
                        $rrHeader['type'],
                        $rrHeader['ttl'],
                        $parsedData['exchange'],
                        $section,
                        $parsedData['preference'],
                        $rdata
                    );
                    continue;
                }

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
        }

        if ($offset !== $packetLength) {
            throw new RuntimeException("Trailing bytes after DNS response");
        }

        return $records;
    }

    private function writeAll($stream, string $data, string $context): void {
        $written = 0;
        $length = strlen($data);

        while ($written < $length) {
            $result = fwrite($stream, substr($data, $written));
            if ($result === false || $result === 0) {
                $meta = stream_get_meta_data($stream);
                if (($meta['timed_out'] ?? false) === true) {
                    throw new RuntimeException("Timed out while writing {$context}");
                }
                throw new RuntimeException("Failed to write {$context}");
            }
            $written += $result;
        }
    }

    private function readExact($stream, int $length, string $context): string {
        $data = '';

        while (strlen($data) < $length) {
            $chunk = fread($stream, $length - strlen($data));
            if ($chunk === false) {
                throw new RuntimeException("Failed to read {$context}");
            }

            if ($chunk === '') {
                $meta = stream_get_meta_data($stream);
                if (($meta['timed_out'] ?? false) === true) {
                    throw new RuntimeException("Timed out while reading {$context}");
                }
                if (feof($stream)) {
                    throw new RuntimeException("Unexpected EOF while reading {$context}");
                }
                throw new RuntimeException("Zero-length read while reading {$context}");
            }

            $data .= $chunk;
        }

        return $data;
    }

    private function sendQuery(string $query, array $server, bool $useTcp): string {
        $ip = $server[0];
        $port = $server[1];

        $serverKey = $ip . ':' . $port;
        $this->checkRateLimit($serverKey);

        if ($useTcp) {
            $isIPv6 = str_contains($ip, ':');
            $target = $isIPv6 ? "tcp://[{$ip}]" : "tcp://{$ip}";
            $socket = @fsockopen($target, $port, $errno, $errstr, $this->timeout);
            if ($socket === false) {
                throw new RuntimeException("TCP connection failed to {$ip}:{$port}: {$errstr} ({$errno})");
            }

            stream_set_timeout($socket, $this->timeout);

            try {
                $payload = pack('n', strlen($query)) . $query;
                $this->writeAll($socket, $payload, "TCP query to {$ip}:{$port}");

                $header = $this->readExact($socket, 2, "TCP response length from {$ip}:{$port}");
                $responseLengthData = unpack('n', $header);
                if ($responseLengthData === false) {
                    throw new RuntimeException("Failed to unpack TCP response length");
                }

                $responseLength = $responseLengthData[1];
                if ($responseLength === 0) {
                    throw new RuntimeException("Zero-length response from {$ip}:{$port}");
                }

                return $this->readExact(
                    $socket,
                    $responseLength,
                    "TCP response from {$ip}:{$port}"
                );
            } finally {
                fclose($socket);
            }
        }

        $isIPv6 = str_contains($ip, ':');
        $family = $isIPv6 ? AF_INET6 : AF_INET;

        $socket = @socket_create($family, SOCK_DGRAM, SOL_UDP);
        if ($socket === false) {
            throw new RuntimeException("UDP socket creation failed for " . ($isIPv6 ? 'IPv6' : 'IPv4'));
        }

        try {
            if (!socket_set_option(
                $socket,
                SOL_SOCKET,
                SO_RCVTIMEO,
                ['sec' => $this->timeout, 'usec' => 0]
            )) {
                throw new RuntimeException("Failed to set UDP receive timeout");
            }

            if (!socket_set_option(
                $socket,
                SOL_SOCKET,
                SO_SNDTIMEO,
                ['sec' => $this->timeout, 'usec' => 0]
            )) {
                throw new RuntimeException("Failed to set UDP send timeout");
            }

            if (!@socket_connect($socket, $ip, $port)) {
                $errorCode = socket_last_error($socket);
                throw new RuntimeException(
                    "UDP connection failed to {$ip}:{$port}: " . socket_strerror($errorCode)
                );
            }

            $sent = @socket_send($socket, $query, strlen($query), 0);
            if ($sent === false || $sent !== strlen($query)) {
                $errorCode = socket_last_error($socket);
                throw new RuntimeException(
                    "UDP send failed to {$ip}:{$port}: " . socket_strerror($errorCode)
                );
            }

            $response = '';
            $bytes = @socket_recv($socket, $response, self::MAX_UDP_SIZE, 0);
            if ($bytes === false) {
                $errorCode = socket_last_error($socket);
                throw new RuntimeException(
                    "UDP receive failed from {$ip}:{$port}: " . socket_strerror($errorCode)
                );
            }

            if ($bytes === 0) {
                throw new RuntimeException("Empty UDP response from {$ip}:{$port}");
            }

            return $response;
        } finally {
            socket_close($socket);
        }
    }

    private function getCacheKey(string $domain, int $queryType, array $server, bool $useTcp): string {
        $normalizedDomain = $domain === '' || $domain === '.'
            ? '.'
            : strtolower(rtrim($domain, '.'));
        $serverKey = $server[0] . ':' . $server[1];
        $transport = $useTcp ? 'tcp' : 'udp';
        $dnssec = $this->requestDnssec ? 'dnssec' : 'plain';
        return hash('sha256', "{$normalizedDomain}:{$queryType}:{$serverKey}:{$transport}:{$dnssec}");
    }

    public function resolve(
        string $domain,
        $queryType = DNSRecordType::A,
        ?array $server = null,
        bool $followCnames = true,
        int $cnameDepth = 0
    ): array {
        if ($cnameDepth > self::MAX_CNAME_REDIRECTS) {
            throw new RuntimeException(
                "Too many CNAME redirects (max " . self::MAX_CNAME_REDIRECTS . ")"
            );
        }

        $originalDomain = $domain;
        $domain = $domain === '.' ? '.' : rtrim($domain, '.');

        if (!$this->isValidDomain($domain)) {
            throw new InvalidArgumentException("Invalid domain format: {$originalDomain}");
        }

        if (is_array($queryType)) {
            $results = [];
            $errors = [];

            foreach ($queryType as $qt) {
                try {
                    $qtInt = is_string($qt)
                        ? DNSRecordType::getTypeFromName(trim($qt))
                        : $qt;

                    if (!is_int($qtInt)) {
                        throw new InvalidArgumentException("Invalid query type: {$qt}");
                    }

                    $typeResults = $this->resolve(
                        $domain,
                        $qtInt,
                        $server,
                        $followCnames,
                        $cnameDepth
                    );
                    $results = array_merge($results, $typeResults);
                } catch (Exception $e) {
                    $errors[] = (string)$qt . ': ' . $e->getMessage();
                    if ($this->debug) {
                        error_log(
                            "Failed to resolve {$qt} for {$domain}: " . $e->getMessage()
                        );
                    }
                }
            }

            if (empty($results) && !empty($errors)) {
                throw new RuntimeException(
                    "All query types failed: " . implode('; ', $errors)
                );
            }

            return $results;
        }

        if (is_string($queryType)) {
            $queryTypeInt = DNSRecordType::getTypeFromName(trim($queryType));
            if ($queryTypeInt === null) {
                if (ctype_digit(trim($queryType))) {
                    $numericType = (int)trim($queryType);
                    if ($numericType < 0 || $numericType > 65535) {
                        throw new InvalidArgumentException(
                            "Unsupported query type: {$queryType}"
                        );
                    }
                    $queryTypeInt = $numericType;
                } else {
                    throw new InvalidArgumentException(
                        "Unsupported query type: {$queryType}"
                    );
                }
            }
            $queryType = $queryTypeInt;
        }

        if (!is_int($queryType) || $queryType < 0 || $queryType > 65535) {
            throw new InvalidArgumentException("Invalid query type");
        }

        $servers = $server !== null ? [$server] : array_values($this->dnsServers);
        $lastErrors = [];

        for ($attempt = 0; $attempt < $this->retries; $attempt++) {
            foreach ($servers as $currentServer) {
                $useTcp = $this->defaultUseTcp;

                for ($tcpAttempt = 0; $tcpAttempt < 2; $tcpAttempt++) {
                    $cacheKey = $this->enableCache
                        ? $this->getCacheKey(
                            $domain,
                            $queryType,
                            $currentServer,
                            $useTcp
                        )
                        : null;

                    if ($cacheKey !== null) {
                        $cached = $this->cache->get($cacheKey);
                        if ($cached !== null) {
                            if ($this->debug) {
                                error_log(
                                    "Cache hit for {$domain} (" .
                                    DNSRecordType::getName($queryType) .
                                    ") via {$currentServer[0]}:" .
                                    "{$currentServer[1]}"
                                );
                            }
                            return $cached;
                        }
                    }

                    try {
                        $serverKey = $currentServer[0] . ':' . $currentServer[1];
                        $this->queryStats[$serverKey] =
                            ($this->queryStats[$serverKey] ?? 0) + 1;

                        [$query, $tid] = $this->buildQuery($domain, $queryType);
                        $startTime = microtime(true);

                        $data = $this->sendQuery(
                            $query,
                            $currentServer,
                            $useTcp
                        );

                        if ($data === '') {
                            throw new RuntimeException(
                                "Empty response from DNS server"
                            );
                        }

                        $records = $this->parseResponse(
                            $data,
                            $tid,
                            $domain,
                            $queryType
                        );

                        $finalRecords = [];

                        if ($queryType === DNSRecordType::ANY) {
                            $finalRecords = $records;
                        } else {
                            $targetRecords = [];
                            $cnameRecords = [];

                            foreach ($records as $record) {
                                if ($record->section !== 'answer') {
                                    continue;
                                }

                                if ($record->type === $queryType) {
                                    $targetRecords[] = $record;
                                } elseif ($record->type === DNSRecordType::CNAME) {
                                    $cnameRecords[] = $record;
                                }
                            }

                            if (!empty($targetRecords)) {
                                $finalRecords = array_values($targetRecords);
                            } elseif ($followCnames && !empty($cnameRecords)) {
                                $cnameRecord = reset($cnameRecords);
                                $cnameTarget = $cnameRecord->data;

                                if (!is_string($cnameTarget) || $cnameTarget === '') {
                                    throw new RuntimeException(
                                        "Invalid CNAME target"
                                    );
                                }

                                if ($this->debug) {
                                    error_log(
                                        "Following CNAME {$domain} -> {$cnameTarget}"
                                    );
                                }

                                $finalRecords = $this->resolve(
                                    $cnameTarget,
                                    $queryType,
                                    $server ?? $currentServer,
                                    true,
                                    $cnameDepth + 1
                                );
                            }
                        }

                        if (!empty($finalRecords)) {
                            $elapsed = (microtime(true) - $startTime) * 1000;

                            if ($this->debug) {
                                error_log(
                                    "Resolved {$domain} (" .
                                    DNSRecordType::getName($queryType) .
                                    ") via {$currentServer[0]} in {$elapsed}ms" .
                                    ($useTcp ? " (TCP)" : " (UDP)")
                                );
                            }

                            if ($cacheKey !== null) {
                                $this->cache->put($cacheKey, $finalRecords);
                            }

                            return $finalRecords;
                        }

                        $lastErrors[] =
                            "{$currentServer[0]}:{$currentServer[1]} - " .
                            "No matching answer records";
                        break;
                    } catch (TruncatedResponseException $e) {
                        if (!$useTcp) {
                            if ($this->debug) {
                                error_log(
                                    "Response truncated, retrying with TCP for " .
                                    $currentServer[0]
                                );
                            }
                            $useTcp = true;
                            continue;
                        }

                        $lastErrors[] =
                            "{$currentServer[0]}:{$currentServer[1]} - " .
                            get_class($e) . ": " . $e->getMessage();
                        break;
                    } catch (Exception $e) {
                        $errorMsg =
                            "{$currentServer[0]}:{$currentServer[1]} - " .
                            get_class($e) . ": " . $e->getMessage();
                        $lastErrors[] = $errorMsg;

                        if ($this->debug) {
                            error_log(
                                "Attempt " . ($attempt + 1) .
                                " failed: {$errorMsg}"
                            );
                        }

                        break;
                    }
                }
            }

            if ($attempt < $this->retries - 1) {
                $delay = min((2 ** $attempt) * 100000, 1000000);
                usleep($delay);
            }
        }

        throw new RuntimeException(
            "All {$this->retries} attempts failed. Errors: " .
            implode('; ', $lastErrors)
        );
    }

    public function query(
        string $domain,
        $queryType = "A",
        ?array $server = null,
        bool $verbose = false,
        bool $jsonOutput = false,
        bool $followCnames = true
    ): array {
        $records = $this->resolve($domain, $queryType, $server, $followCnames);
        
        if ($jsonOutput) {
            $typeDisplay = '';
            if (is_string($queryType)) {
                $typeDisplay = $queryType;
            } elseif (is_array($queryType)) {
                $typeNames = [];
                foreach ($queryType as $qt) {
                    if (is_string($qt)) {
                        $typeNames[] = $qt;
                    } elseif (is_int($qt)) {
                        $typeNames[] = DNSRecordType::getName($qt);
                    }
                }
                $typeDisplay = implode(',', $typeNames);
            } elseif (is_int($queryType)) {
                $typeDisplay = DNSRecordType::getName($queryType);
            }
            
            $result = [
                'domain' => $domain,
                'query_type' => $typeDisplay,
                'timestamp' => date('c'),
                'records' => array_map(fn($r) => $r->toArray(), $records),
                'record_count' => count($records)
            ];
            
            if ($verbose) {
                $result['stats'] = $this->getStats();
                $result['cache_stats'] = $this->cache->getStats();
            }
            
            return $result;
        }

        return $records;
    }

    public function getStats(): array {
        return [
            'query_stats' => $this->queryStats,
            'total_queries' => array_sum($this->queryStats),
            'cache_stats' => $this->cache->getStats(),
            'configuration' => [
                'timeout' => $this->timeout,
                'retries' => $this->retries,
                'use_tcp' => $this->defaultUseTcp,
                'request_dnssec' => $this->requestDnssec,
                'enable_cache' => $this->enableCache,
                'ip_family' => $this->ipFamily,
                'dns_servers' => $this->dnsServers
            ]
        ];
    }

    public function clearCache(): void {
        $this->cache->clear();
    }
}

class TruncatedResponseException extends RuntimeException {
}

function validateServerString(string $serverStr): array {
    $serverStr = trim($serverStr);
    
    if (str_starts_with($serverStr, '[')) {
        $bracketEnd = strpos($serverStr, ']');
        if ($bracketEnd === false) {
            throw new InvalidArgumentException("Invalid IPv6 address format: {$serverStr}");
        }
        
        $ip = substr($serverStr, 1, $bracketEnd - 1);
        $rest = substr($serverStr, $bracketEnd + 1);
        
        if ($ip === '') {
            throw new InvalidArgumentException("Empty IPv6 address");
        }
        
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            throw new InvalidArgumentException("Invalid IPv6 address: {$ip}");
        }
        
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
        $count = count($parts);
        
        if ($count > 2) {
            throw new InvalidArgumentException("Invalid server format: {$serverStr}");
        }
        
        $ip = $parts[0];
        $port = ($count === 2) ? (int)$parts[1] : 53;
        
        if (str_contains($ip, ':') && !str_starts_with($ip, '[')) {
            throw new InvalidArgumentException("IPv6 addresses must be in brackets: {$serverStr}");
        }
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new InvalidArgumentException("Invalid IP address: {$ip}");
        }
    }
    
    if ($port < 1 || $port > 65535) {
        throw new InvalidArgumentException("Invalid port number: {$port}");
    }
    
    return [$ip, $port];
}

function parseCliArguments(array $argv): array {
    $options = [];
    $domain = null;
    $valueOptions = [
        '-t' => 'type',
        '--type' => 'type',
        '-s' => 'server',
        '--server' => 'server'
    ];
    $flagOptions = [
        '--tcp' => 'tcp',
        '--request-dnssec' => 'request-dnssec',
        '--dnssec' => 'dnssec',
        '--no-follow-cnames' => 'no-follow-cnames',
        '-v' => 'verbose',
        '--verbose' => 'verbose',
        '--json' => 'json',
        '--debug' => 'debug',
        '--ipv6-only' => 'ipv6-only',
        '--ipv4-only' => 'ipv4-only',
        '--no-cache' => 'no-cache',
        '--help' => 'help',
        '--stats' => 'stats'
    ];

    for ($i = 1; $i < count($argv); $i++) {
        $arg = $argv[$i];

        if ($arg === '--') {
            if ($i + 1 < count($argv)) {
                if ($domain !== null) {
                    throw new InvalidArgumentException("Multiple domain names provided");
                }
                $domain = $argv[++$i];
            }
            if ($i + 1 < count($argv)) {
                throw new InvalidArgumentException("Unexpected extra arguments");
            }
            break;
        }

        if (isset($valueOptions[$arg])) {
            if ($i + 1 >= count($argv)) {
                throw new InvalidArgumentException("Missing value for {$arg}");
            }
            $options[$valueOptions[$arg]] = $argv[++$i];
            continue;
        }

        if (str_starts_with($arg, '--type=')) {
            $options['type'] = substr($arg, 7);
            continue;
        }

        if (str_starts_with($arg, '--server=')) {
            $options['server'] = substr($arg, 9);
            continue;
        }

        if (isset($flagOptions[$arg])) {
            $options[$flagOptions[$arg]] = true;
            continue;
        }

        if (str_starts_with($arg, '-')) {
            throw new InvalidArgumentException("Unknown option: {$arg}");
        }

        if ($domain !== null) {
            throw new InvalidArgumentException("Multiple domain names provided");
        }

        $domain = $arg;
    }

    return [$domain, $options];
}

function printUsage(): void {
    echo "Usage: php dns_resolver.php [options] <domain>\n";
    echo "       php dns_resolver.php <domain> [options]\n";
    echo "Options:\n";
    echo "  -t, --type <type>          DNS record type or comma-separated list\n";
    echo "  -s, --server <ip:port>     Specific DNS server\n";
    echo "  --tcp                      Use TCP instead of UDP\n";
    echo "  --request-dnssec, --dnssec Request DNSSEC records\n";
    echo "  --no-follow-cnames         Disable following CNAME records\n";
    echo "  -v, --verbose              Verbose output\n";
    echo "  --json                     Output in JSON format\n";
    echo "  --debug                    Enable debug logging\n";
    echo "  --stats                    Show resolver statistics\n";
    echo "  --ipv6-only                Use only IPv6 DNS servers\n";
    echo "  --ipv4-only                Use only IPv4 DNS servers\n";
    echo "  --no-cache                 Disable response caching\n";
    echo "  --help                     Show this help\n";
}

if (PHP_SAPI === 'cli') {
    try {
        [$domain, $options] = parseCliArguments($argv);
    } catch (Exception $e) {
        fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
        exit(1);
    }

    if (isset($options['help'])) {
        printUsage();
        exit(0);
    }

    if ($domain === null) {
        printUsage();
        exit(1);
    }

    $queryType = $options['type'] ?? 'A';
    $server = $options['server'] ?? null;
    $useTcp = isset($options['tcp']);
    $requestDnssec = isset($options['request-dnssec']) || isset($options['dnssec']);
    $noFollowCnames = isset($options['no-follow-cnames']);
    $verbose = isset($options['verbose']);
    $jsonOutput = isset($options['json']);
    $debug = isset($options['debug']);
    $ipv6Only = isset($options['ipv6-only']);
    $ipv4Only = isset($options['ipv4-only']);
    $noCache = isset($options['no-cache']);
    $showStats = isset($options['stats']);
    
    if ($debug) {
        error_reporting(E_ALL);
        ini_set('display_errors', 1);
    }
    
    try {
        $serverConfig = null;
        if ($server) {
            $serverConfig = validateServerString($server);
        }
        
        $ipFamily = null;
        if ($ipv6Only) {
            $ipFamily = 'ipv6';
        } elseif ($ipv4Only) {
            $ipFamily = 'ipv4';
        }
        
        $resolver = new DNSResolver(
            dnsServers: null,
            timeout: 3,
            retries: 3,
            useTcp: $useTcp,
            requestDnssec: $requestDnssec,
            enableCache: !$noCache,
            maxCacheSize: 1024,
            debug: $debug,
            ipFamily: $ipFamily
        );
        
        if ($showStats) {
            $stats = $resolver->getStats();
            if ($jsonOutput) {
                echo json_encode($stats, JSON_PRETTY_PRINT) . "\n";
            } else {
                echo "\nResolver Statistics:\n";
                echo "Total queries: " . $stats['total_queries'] . "\n";
                echo "DNS Servers:\n";
                foreach ($stats['configuration']['dns_servers'] as $srv) {
                    echo "  {$srv[0]}:{$srv[1]}\n";
                }
                echo "\nCache Statistics:\n";
                $cacheStats = $stats['cache_stats'];
                echo "  Size: {$cacheStats['size']}/{$cacheStats['max_size']}\n";
                echo "  Hits: {$cacheStats['hits']}\n";
            }
            exit(0);
        }
        
        $queryTypes = str_contains($queryType, ',') ? array_map('trim', explode(',', $queryType)) : trim($queryType);
        
        $result = $resolver->query(
            $domain,
            queryType: $queryTypes,
            server: $serverConfig,
            verbose: $verbose,
            jsonOutput: $jsonOutput,
            followCnames: !$noFollowCnames
        );
        
        if ($jsonOutput) {
            echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        } else {
            $typeDisplay = '';
            if (is_string($queryTypes)) {
                $typeDisplay = $queryTypes;
            } elseif (is_array($queryTypes)) {
                $typeNames = [];
                foreach ($queryTypes as $qt) {
                    if (is_string($qt)) {
                        $typeNames[] = $qt;
                    } elseif (is_int($qt)) {
                        $typeNames[] = DNSRecordType::getName($qt);
                    }
                }
                $typeDisplay = implode(',', $typeNames);
            }
            
            echo "\nDNS {$typeDisplay} records for {$domain}:\n";
            
            $sections = [];
            foreach ($result as $r) {
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
        }
    } catch (Exception $e) {
        $errorMessage = "Error: " . $e->getMessage();
        if ($jsonOutput) {
            echo json_encode(['error' => $errorMessage], JSON_PRETTY_PRINT) . "\n";
        } else {
            echo "{$errorMessage}\n";
        }
        exit(1);
    }
}
