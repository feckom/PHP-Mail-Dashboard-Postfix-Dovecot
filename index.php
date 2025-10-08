<?php
declare(strict_types=1);
mb_internal_encoding('UTF-8');

const CACHE_DIR      = __DIR__ . '/.cache';
const CACHE_LOGSRC   = CACHE_DIR . '/logsource.json';
const CACHE_INDEX    = CACHE_DIR . '/index.json';
const CACHE_AGG      = CACHE_DIR . '/agg.json';
const CACHE_HEALTH   = CACHE_DIR . '/health.json';

const BIN_POSTQUEUE  = '/usr/sbin/postqueue';
const BIN_DOVEADM    = '/usr/bin/doveadm';
const BIN_SS         = '/usr/bin/ss';
const BIN_ZGREP      = '/usr/bin/zgrep';
const BIN_GREP       = '/usr/bin/grep';
const BIN_DF         = '/usr/bin/df';
const BIN_FREE       = '/usr/bin/free';
const BIN_UPTIME     = '/usr/bin/uptime';
const BIN_HOSTCTL    = '/usr/bin/hostnamectl';
const BIN_JOURNALCTL = '/usr/bin/journalctl';

const LOG_CANDIDATES = [
    '/var/log/mail.log*',
    '/var/log/maillog*',
    '/var/log/mail/*.log*',
];

const DETECT_REFRESH_SEC = 3600;
const SCAN_TIMEOUT       = 15;
const JOURNAL_UNITS      = ['postfix', 'dovecot'];

if (!is_dir(CACHE_DIR)) @mkdir(CACHE_DIR, 0777, true);

function run(array $argv, int $timeout = SCAN_TIMEOUT): array {
    array_unshift($argv, 'sudo', '-n');
    $desc = [0=>['pipe','r'], 1=>['pipe','w'], 2=>['pipe','w']];
    $p = proc_open($argv, $desc, $pipes);
    if (!\is_resource($p)) return [1,'','proc_open_failed'];
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out=''; $err=''; $start=microtime(true);
    while (true) {
        $out .= stream_get_contents($pipes[1]);
        $err .= stream_get_contents($pipes[2]);
        $st = proc_get_status($p);
        if (!$st['running']) break;
        if ((microtime(true)-$start) > $timeout) { proc_terminate($p); break; }
        usleep(100000);
    }
    foreach ($pipes as $pp) if (\is_resource($pp)) fclose($pp);
    $code = proc_close($p);
    return [$code,$out,$err];
}
function jsonOut($data): void {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
    exit;
}
function readJson(string $f, $fallback) {
    if (!is_file($f)) return $fallback;
    $s = @file_get_contents($f);
    if ($s === false || $s === '') return $fallback;
    $j = json_decode($s, true);
    return (is_array($j) || is_object($j)) ? $j : $fallback;
}
function writeJson(string $f, $data): void {
    @file_put_contents($f, json_encode($data, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT));
}

function serverTZ(): string { return @date_default_timezone_get() ?: 'UTC'; }

function parseLogTimestamp(string $line, ?int $assumedYear = null): ?int {
    if (preg_match('/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2}))/u', $line, $m)) {
        try { $dt = new DateTimeImmutable($m[1]); return $dt->getTimestamp(); } catch (Throwable $e) {}
    }
    if (preg_match('/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/u', $line, $m)) {
        static $mon = ['Jan'=>1,'Feb'=>2,'Mar'=>3,'Apr'=>4,'May'=>5,'Jun'=>6,'Jul'=>7,'Aug'=>8,'Sep'=>9,'Oct'=>10,'Nov'=>11,'Dec'=>12];
        $y = $assumedYear ?? (int)date('Y');
        $month = $mon[$m[1]] ?? (int)date('n');
        $day   = (int)$m[2]; $h=(int)$m[3]; $mi=(int)$m[4]; $s=(int)$m[5];
        $dt = DateTimeImmutable::createFromFormat('Y-n-j H:i:s', sprintf('%d-%d-%d %02d:%02d:%02d', $y, $month, $day, $h, $mi, $s));
        if ($dt) return $dt->getTimestamp();
    }
    return null;
}

function detectType(string $line): ?string {
    if (preg_match('/\bstatus=sent\b/i', $line)) return 'sent';
    if (preg_match('/postfix\/(local|virtual|pipe).*status=sent/i', $line)) return 'sent';
    if (preg_match('/dovecot-lda.*saved mail to/i', $line)) return 'sent';
    if (preg_match('/\bstatus=(deferred|bounced)\b/i', $line)) return 'failed_delivery';
    if (preg_match('/postfix\/smtpd.*client=|postfix\/cleanup|qmgr:.*\bfrom=/i', $line)) return 'incoming';
    if (preg_match('/NOQUEUE:\s*reject|[\s]reject(\b|:)|blocked|policy|blacklist|RBL|greylist(ed)?/i', $line)) return 'rejected';
    if (preg_match('/(amavis|rspamd|clamd|clamav).*(reject|discard|virus|malware|spam)|\b(spam|virus)\s+(reject|discard|found)\b/i', $line)) return 'spam_virus';
    if (preg_match('/quota|mail(box)?\s*full|exceed(ed)?\s*storage/i', $line)) return 'quota_fail';
    if (preg_match('/SASL\s+(LOGIN|PLAIN)\s+authentication\s+failed|auth(entication)?\s+failed/i', $line)) return 'auth_fail';
    return null;
}

function listFilesForGlob(string $glob): array {
    $files = glob($glob) ?: [];
    sort($files, SORT_STRING);
    return $files;
}
function binsPresent(): array {
    $bins = ['grep'=>BIN_GREP,'zgrep'=>BIN_ZGREP,'journalctl'=>BIN_JOURNALCTL,'postqueue'=>BIN_POSTQUEUE,'doveadm'=>BIN_DOVEADM];
    $out = [];
    foreach ($bins as $k=>$p) $out[$k] = is_file($p);
    return $out;
}

function detectLogSource(bool $force = false): array {
    $now = time();
    $cached = readJson(CACHE_LOGSRC, []);
    if (!$force && !empty($cached['source']['picked_at']) && ($now - (int)$cached['source']['picked_at'] < DETECT_REFRESH_SEC)) {
        return $cached;
    }

    $pickedGlob = null;
    $filesPicked = [];
    $scanned = [];

    foreach (LOG_CANDIDATES as $glob) {
        $files = listFilesForGlob($glob);
        $scanned[] = ['glob'=>$glob,'files'=>count($files)];
        if (!$filesPicked && $files) {
            $pickedGlob = $glob;
            $filesPicked = $files;
            break;
        }
    }

    if (!$pickedGlob) {
        [$code, $out] = run([BIN_JOURNALCTL, '--no-pager', '-n', '50', ...array_map(fn($u)=>['-u',$u], JOURNAL_UNITS)]);
        if ($code === 0) {
            $pickedGlob = 'journal';
            $filesPicked = [];
        }
    }

    $src = [
        'source'=>[
            'glob'=>$pickedGlob,
            'picked_at'=>$now,
            'scanned'=>$scanned,
            'server_tz'=>serverTZ(),
        ],
        'readable_files'=>$filesPicked,
        'bins_present'=>binsPresent(),
        'server_tz'=>serverTZ(),
        'index_meta'=>readJson(CACHE_INDEX, ['files'=>0,'updated'=>0]),
        'agg_ts'=> (int) (readJson(CACHE_AGG, [])['updated_at'] ?? 0),
    ];
    writeJson(CACHE_LOGSRC, $src);
    return $src;
}

function currentFiles(): array {
    $src = detectLogSource(false);
    if (($src['source']['glob'] ?? null) === 'journal') return [];
    return $src['readable_files'] ?? [];
}
function activePlainFile(): ?string {
    foreach (currentFiles() as $f) {
        if (substr($f, -3) === '.gz') continue;
        if (preg_match('~/maillog$|/mail\.log$~', $f)) return $f;
    }
    foreach (currentFiles() as $f) if (substr($f, -3) !== '.gz') return $f;
    return null;
}

function statusRegex(): string {
    return '(status=sent|status=(deferred|bounced)|NOQUEUE:\s*reject|[\s]reject(\b|:)|blocked|policy|blacklist|RBL|greylist(ed)?|(amavis|rspamd|clamd|clamav)|(spam|virus)\s+(reject|discard|found)|postfix\/smtpd|postfix\/cleanup|qmgr:.*from=|dovecot-lda.*saved mail to|quota|mail(box)?\s*full|SASL\s+(LOGIN|PLAIN)\s+authentication\s+failed|auth(entication)?\s+failed)';
}
function readRelevantFromPlain(string $file, int $sinceTs = 0): array {
    $rx = '~' . statusRegex() . '~i';
    $out = [];
    $assumedYear = (int)date('Y', @filemtime($file) ?: time());
    $fh = @fopen($file, 'rb');
    if (!$fh) return $out;
    while (!feof($fh)) {
        $line = fgets($fh);
        if ($line === false) break;
        if (!preg_match($rx, $line)) continue;
        $ts = parseLogTimestamp($line, $assumedYear);
        if ($ts === null) continue;
        if ($sinceTs > 0 && $ts < $sinceTs) continue;
        $out[] = $line;
    }
    fclose($fh);
    return $out;
}
function zgrepRelevant(array $files): array {
    if (empty($files)) return [];
    $argv = array_merge([BIN_ZGREP, '-h', '-a', '-E', statusRegex()], $files);
    [, $out] = run($argv, 12);
    if ($out === '' || $out === null) return [];
    return explode("\n", trim($out));
}

function journalRelevant(int $sinceTs = 0): array {
    $args = [BIN_JOURNALCTL,'--no-pager','-n','20000'];
    foreach (JOURNAL_UNITS as $u) { $args[]='-u'; $args[]=$u; }
    [, $out] = run($args, 10);
    if (!$out) return [];
    $rx = '~' . statusRegex() . '~i';
    $lines = [];
    $y = (int)date('Y');
    foreach (explode("\n", $out) as $ln) {
        if (!preg_match($rx, $ln)) continue;
        $ts = parseLogTimestamp($ln, $y);
        if ($ts === null) continue;
        if ($sinceTs > 0 && $ts < $sinceTs) continue;
        $lines[] = $ln;
    }
    return $lines;
}

function collectTodayStats(): array {
    $dt = new DateTimeImmutable('now');
    $dateClassic = $dt->format('M j');
    $dateIso     = $dt->format('Y-m-d');

    $plain = activePlainFile();
    $lines = [];
    if ($plain && is_readable($plain)) {
        $todayStart = (new DateTimeImmutable('today'))->getTimestamp();
        $lines = readRelevantFromPlain($plain, $todayStart);
    } else {
        $files = currentFiles();
        if ($files) $lines = zgrepRelevant($files);
        else        $lines = journalRelevant((new DateTimeImmutable('today'))->getTimestamp());
    }

    $stats = ['date'=>$dateClassic, 'incoming'=>0,'sent'=>0,'failed_delivery'=>0,'rejected'=>0,'spam_virus'=>0,'quota_fail'=>0,'auth_fail'=>0];
    foreach ($lines as $ln) {
        if ($ln === '') continue;
        if (strpos($ln, $dateIso) !== 0 && strpos($ln, $dateClassic) !== 0) {
            continue;
        }
        $t = detectType($ln);
        if (!$t) continue;
        if (isset($stats[$t])) $stats[$t]++;
    }
    $tot = max(1, (int)$stats['incoming']);
    $stats['success_rate'] = round(($stats['sent'] / $tot) * 100, 1);
    return $stats;
}

function collectTotals(): array {
    $files = currentFiles();
    if (empty($files)) return ['total_sent'=>0];
    $argv = array_merge([BIN_ZGREP, '-h', '-a', '-E', '-c', 'status=sent'], $files);
    [, $out] = run($argv, 12);
    $total = 0;
    foreach (explode("\n", trim((string)$out)) as $row) { $total += (int)trim($row); }
    return ['total_sent'=>$total];
}

function collectQueue(): array {
    [$code, $o] = run([BIN_POSTQUEUE, '-p'], 8);
    if (trim($o)==='') return ['ok'=>false,'error'=>'postqueue_failed'];
    $total=0; $deferred=0;
    foreach (explode("\n",$o) as $ln) {
        if (preg_match('~^[A-F0-9]{10,}|^\*?[A-F0-9]{10,}~',$ln)) $total++;
        if (stripos($ln,'deferred')!==false) $deferred++;
    }
    return ['ok'=>true,'total'=>$total,'deferred'=>$deferred];
}

function collectSessions(): array {
    [$code,$o] = run([BIN_DOVEADM,'who'],5);
    if ($code===0 && trim($o)!=='') {
        $imap=$pop3=0;
        foreach (explode("\n",trim($o)) as $ln){
            if (stripos($ln,'imap')!==false)$imap++;
            if (stripos($ln,'pop3')!==false)$pop3++;
        }
        return ['imap'=>$imap,'pop3'=>$pop3,'total'=>$imap+$pop3];
    }
    [$c1,$s1]=run([BIN_SS,'-tn','state','established','sport','=',':993'],4);
    [$c2,$s2]=run([BIN_SS,'-tn','state','established','sport','=',':143'],4);
    [$c3,$p1]=run([BIN_SS,'-tn','state','established','sport','=',':995'],4);
    [$c4,$p2]=run([BIN_SS,'-tn','state','established','sport','=',':110'],4);
    $imap = ($c1===0?max(0,substr_count($s1,"\n")-1):0)+($c2===0?max(0,substr_count($s2,"\n")-1):0);
    $pop3 = ($c3===0?max(0,substr_count($p1,"\n")-1):0)+($c4===0?max(0,substr_count($p2,"\n")-1):0);
    return ['imap'=>$imap,'pop3'=>$pop3,'total'=>$imap+$pop3];
}

function collectSystem(): array {
    [, $up]     = run([BIN_UPTIME], 3);
    [, $mem]    = run([BIN_FREE,'-m'], 3);
    [, $disk]   = run([BIN_DF,'-hP','/'], 3);
    [, $host]   = run([BIN_HOSTCTL,'status'], 3);
    $memTotal=$memUsed=0;
    foreach (explode("\n",$mem) as $ln){
        if (preg_match('~^Mem:\s+(\d+)\s+(\d+)~',$ln,$m)){ $memTotal=(int)$m[1]; $memUsed=(int)$m[2]; break; }
    }
    $dl = explode("\n",trim($disk)); $diskInfo=['fs'=>'','size'=>'','used'=>'','avail'=>'','usep'=>'','mount'=>'/'];
    if (count($dl)>=2){ $parts=preg_split('/\s+/',trim($dl[1])); $diskInfo=['fs'=>$parts[0]??'','size'=>$parts[1]??'','used'=>$parts[2]??'','avail'=>$parts[3]??'','usep'=>$parts[4]??'','mount'=>$parts[5]??'/']; }
    $hostLines=[]; foreach (explode("\n",$host) as $ln){ if (stripos($ln,'Static hostname:')!==false||stripos($ln,'Operating System:')!==false||stripos($ln,'Kernel:')!==false){ $hostLines[]=trim($ln);} }
    return ['uptime'=>trim(preg_replace('/\s+/',' ',$up)),'mem_mb'=>['total'=>$memTotal,'used'=>$memUsed],'disk_root'=>$diskInfo,'host'=>implode(' | ',$hostLines)];
}

function bucketSeries(array $labels): array {
    $n=count($labels);
    return [
        'incoming'=>array_fill(0,$n,0),
        'sent'=>array_fill(0,$n,0),
        'failed_delivery'=>array_fill(0,$n,0),
        'quota_fail'=>array_fill(0,$n,0),
        'rejected'=>array_fill(0,$n,0),
        'spam_virus'=>array_fill(0,$n,0),
        'auth_fail'=>array_fill(0,$n,0),
    ];
}
function linesForRange(int $start, int $end): array {
    $plain = activePlainFile();
    if ($plain && is_readable($plain)) return readRelevantFromPlain($plain, $start);
    $files = currentFiles();
    if ($files) return zgrepRelevant($files);
    return journalRelevant($start);
}
function seriesLive(): array {
    $end = time(); $start = $end - 3600; $step = 300;
    $labels=[]; for($t=$start; $t<=$end; $t+=$step){ $labels[] = date('H:i',$t); }
    $b = bucketSeries($labels);
    $lines = linesForRange($start, $end);
    $year = (int)date('Y');
    foreach ($lines as $ln) {
        if ($ln==='') continue;
        $ts = parseLogTimestamp($ln, $year);
        if ($ts===null || $ts<$start || $ts>$end) continue;
        $idx = (int)floor(($ts-$start)/$step);
        if (!isset($labels[$idx])) continue;
        $t=detectType($ln);
        if (!$t || !isset($b[$t])) continue;
        $b[$t][$idx]++;
    }
    return ['labels'=>$labels]+$b;
}
function seriesToday(): array {
    $y=(int)date('Y'); $m=(int)date('n'); $d=(int)date('j');
    $start = (new DateTimeImmutable(sprintf('%d-%02d-%02d 00:00:00',$y,$m,$d)))->getTimestamp();
    $end     = $start + 24*3600 - 1;
    $labels=[]; for($h=0;$h<24;$h++) $labels[]=sprintf('%02d:00',$h);
    $b = bucketSeries($labels);
    $lines = linesForRange($start, $end);
    foreach ($lines as $ln) {
        if ($ln==='') continue;
        $ts = parseLogTimestamp($ln, $y);
        if ($ts===null || $ts<$start || $ts>$end) continue;
        $h = (int)date('G',$ts);
        $t=detectType($ln); if (!$t || !isset($b[$t])) continue;
        $b[$t][$h]++;
    }
    unset($b['auth_fail']);
    return ['labels'=>$labels]+$b;
}
function seriesWeek(): array {
    $now = new DateTimeImmutable('now');
    $y=(int)$now->format('Y');
    $labels=[]; $dayStarts=[];
    for ($i=6; $i>=0; $i--) {
        $d = $now->sub(new DateInterval('P'.$i.'D'))->setTime(0,0,0);
        $labels[] = $d->format('M j');
        $dayStarts[] = $d->getTimestamp();
    }
    $dayEnds = $dayStarts;
    for ($i=0;$i<count($dayEnds)-1;$i++) $dayEnds[$i] = $dayStarts[$i+1]-1;
    $dayEnds[count($dayEnds)-1] = $now->setTime(23,59,59)->getTimestamp();

    $b = bucketSeries($labels);
    $lines = linesForRange($dayStarts[0], $dayEnds[count($dayEnds)-1]);
    $n = count($labels);
    foreach ($lines as $ln) {
        if ($ln==='') continue;
        $ts = parseLogTimestamp($ln, $y);
        if ($ts===null) continue;
        for ($i=0;$i<$n;$i++) {
            if ($ts >= $dayStarts[$i] && $ts <= $dayEnds[$i]) {
                $t=detectType($ln); if (!$t || !isset($b[$t])) break;
                $b[$t][$i]++; break;
            }
        }
    }
    unset($b['auth_fail']);
    return ['labels'=>$labels]+$b;
}
function seriesMonth(): array {
    $now=new DateTimeImmutable('now');
    $y=(int)$now->format('Y');
    $labels=[]; $dayStarts=[];
    for($i=29;$i>=0;$i--){
        $d=$now->sub(new DateInterval('P'.$i.'D'))->setTime(0,0,0);
        $labels[]=$d->format('M j');
        $dayStarts[]=$d->getTimestamp();
    }
    $dayEnds=$dayStarts;
    for($i=0;$i<count($dayEnds)-1;$i++)$dayEnds[$i]=$dayStarts[$i+1]-1;
    $dayEnds[count($dayEnds)-1]=$now->setTime(23,59,59)->getTimestamp();

    $lines=linesForRange($dayStarts[0], $dayEnds[count($dayEnds)-1]);
    $n=count($labels);
    $incoming=array_fill(0,$n,0);
    $sent=array_fill(0,$n,0);
    $failed=array_fill(0,$n,0);

    foreach($lines as $ln){
        if ($ln==='') continue;
        $ts=parseLogTimestamp($ln,$y);
        if($ts===null)continue;
        for($i=0;$i<$n;$i++){
            if($ts>=$dayStarts[$i]&&$ts<=$dayEnds[$i]){
                $t=detectType($ln);
                if($t==='incoming')$incoming[$i]++;
                elseif($t==='sent')$sent[$i]++;
                elseif($t==='failed_delivery')$failed[$i]++;
                break;
            }
        }
    }
    return ['labels'=>$labels,'incoming'=>$incoming,'sent'=>$sent,'failed'=>$failed];
}

function healthInfo(): array {
    $src = detectLogSource(false);
    $plain = activePlainFile();
    $canReadPlain = $plain && is_readable($plain);
    $bins = binsPresent();

    $lastMin = time()-60;
    $recent = 0;
    if ($canReadPlain) $recent = count(readRelevantFromPlain($plain, $lastMin));
    elseif (!empty($src['readable_files'])) $recent = count(zgrepRelevant($src['readable_files']));
    else $recent = count(journalRelevant($lastMin));

    $warn = [];
    if (empty($src['readable_files']) && (($src['source']['glob'] ?? '')!=='journal')) $warn[]='no_readable_log_files';
    if (!$bins['zgrep']) $warn[]='zgrep_missing';

    return [
        'source'=>$src['source'] ?? [],
        'readable_files'=>$src['readable_files'] ?? [],
        'bins_present'=>$bins,
        'sudo_mode_used'=>true,
        'server_tz'=>serverTZ(),
        'active_plain'=>$plain,
        'recent_60s_rows'=>$recent,
        'note'=> $canReadPlain ? 'using plain file for live/today' : (!empty($src['readable_files']) ? 'using zgrep over files' : 'journal fallback'),
        'warnings'=> $warn,
    ];
}

/* -------- NEW: Top Senders / Recipients -------- */
function collectTopTalkers(int $sinceTs, int $limit = 10): array {
    $lines = linesForRange($sinceTs, time());
    $senders = [];
    $recipients = [];

    foreach ($lines as $line) {
        // Find sender
        if (preg_match('/from=<([^>]+)>/i', $line, $matches)) {
            $sender = strtolower($matches[1]);
            if ($sender) $senders[$sender] = ($senders[$sender] ?? 0) + 1;
        }
        // Find recipient for successfully sent messages
        if (preg_match('/to=<([^>]+)>.+status=sent/i', $line, $matches)) {
            $recipient = strtolower($matches[1]);
            if ($recipient) $recipients[$recipient] = ($recipients[$recipient] ?? 0) + 1;
        }
    }
    
    arsort($senders);
    arsort($recipients);

    return [
        'senders' => array_slice($senders, 0, $limit, true),
        'recipients' => array_slice($recipients, 0, $limit, true)
    ];
}


/* -------- API router -------- */
if (isset($_GET['api'])) {
    try {
        switch ($_GET['api']) {
            case 'ping':          jsonOut(['ok'=>true,'time'=>time()]);
            case 'health':        jsonOut(healthInfo());
            case 'source':        jsonOut(detectLogSource(false));
            case 'today':         jsonOut(collectTodayStats());
            case 'totals':        jsonOut(collectTotals());
            case 'queue':         jsonOut(collectQueue());
            case 'sessions':      jsonOut(collectSessions());
            case 'system':        jsonOut(collectSystem());
            case 'series_live':   jsonOut(seriesLive());
            case 'series_today':  jsonOut(seriesToday());
            case 'series_week':   jsonOut(seriesWeek());
            case 'series_month':  jsonOut(seriesMonth());
            // NEW API Endpoints
            case 'top_day':       jsonOut(collectTopTalkers((new DateTime('today'))->getTimestamp()));
            case 'top_week':      jsonOut(collectTopTalkers((new DateTime('-6 days'))->setTime(0,0)->getTimestamp()));
            case 'top_month':     jsonOut(collectTopTalkers((new DateTime('-29 days'))->setTime(0,0)->getTimestamp()));
            default:              jsonOut(['error'=>'unknown_api']);
        }
    } catch (Throwable $e) {
        http_response_code(500);
        jsonOut(['error'=>'exception','message'=>$e->getMessage()]);
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Mail Dashboard — Extended Stats</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0a0d12;--panel:#0f1419;--accent:#4cc9f0;--ok:#16a34a;--warn:#f59e0b;--err:#ef4444;--muted:#8b95a5;--txt:#e6edf3;--grid-gap:12px}
*{box-sizing:border-box} body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;background:var(--bg);color:var(--txt);font-size:13px}
header{padding:10px 14px;background:#080a0e;border-bottom:1px solid #1b2230;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
h1{font-size:16px;margin:0}
small{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:var(--grid-gap);padding:12px}
@media(max-width:1400px){.grid{grid-template-columns:repeat(3,1fr)}}
@media(max-width:1000px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:640px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid #1a1f29;border-radius:12px;padding:12px;box-shadow:0 2px 8px rgba(0,0,0,.25)}
.card h2{font-size:12px;margin:0 0 6px;color:#9aa6b2;letter-spacing:.2px}
.kpis{display:flex;gap:6px;flex-wrap:wrap}
.kpi{background:#0a0e14;padding:8px 10px;border-radius:8px;border:1px solid #1a1f29;min-width:64px;text-align:center}
.kpi .v{font-size:16px;font-weight:700}
.kpi .l{font-size:9px;color:var(--muted);margin-top:2px;text-transform:uppercase;letter-spacing:.3px}
.row{display:flex;gap:8px;align-items:center;justify-content:space-between;margin:4px 0;font-size:11px}
.badge{padding:4px 10px;border-radius:999px;font-size:11px;font-weight:700;border:1px solid transparent}
.badge.ok{background:rgba(22,163,74,.12);color:#9ae6b4;border-color:rgba(22,163,74,.35)}
.badge.warn{background:rgba(245,158,11,.12);color:#ffd166;border-color:rgba(245,158,11,.35)}
.badge.err{background:rgba(239,68,68,.12);color:#fecaca;border-color:rgba(239,68,68,.35)}
.alertbar{display:flex;gap:12px}
.alert{flex:1;background:#0e131a;border:1px solid #1b2230;border-radius:10px;padding:8px 10px;display:flex;align-items:center;justify-content:space-between}
.alert .title{font-weight:700}
.alert .value{font-family:ui-monospace,monospace}
.footer{color:var(--muted);font-size:10px;padding:8px 12px;text-align:right;border-top:1px solid #1b2230}
code{background:#0a0e14;padding:2px 5px;border-radius:4px;border:1px solid #1a1f29;color:#d2d9e3;font-size:10px}
canvas{width:100%;max-height:220px}
.refresh{color:var(--muted);font-size:10px}
ul.mini{margin:6px 0 0 14px;padding:0;line-height:1.3}
ul.mini li{margin-bottom:2px;color:#9aa6b2}
/* NEW STYLES for tables */
.table-container{display:flex;gap:var(--grid-gap);margin-top:10px}
.table-wrapper{flex:1;min-width:0}
.table-wrapper h3{font-size:11px;margin:0 0 4px;color:var(--muted)}
table.mini-table{width:100%;border-collapse:collapse;font-size:10px}
table.mini-table th,table.mini-table td{padding:4px 6px;text-align:left;border-bottom:1px solid #1b2230}
table.mini-table th{font-weight:normal;color:var(--muted)}
table.mini-table td:last-child{text-align:right;font-weight:700}
table.mini-table tr:last-child td{border-bottom:0}
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
<header>
  <h1>📫 Mail Dashboard <small>· Extended · Postfix &amp; Dovecot</small></h1>
  <div class="refresh">KPIs: <code>5s</code> · Charts: <code>30s</code> · Tables: <code>60s</code></div>
</header>

<div class="grid">
  <div class="card" style="grid-column:1/span 4">
    <div class="alertbar">
      <div class="alert" id="alert-mail">
        <span class="title">Mail Flow</span>
        <span class="badge ok" id="alert-mail-badge">Unknown</span>
      </div>
      <div class="alert" id="alert-queue">
        <span class="title">Queue</span>
        <span class="badge ok" id="alert-queue-badge">–</span>
      </div>
      <div class="alert" id="alert-auth">
        <span class="title">Auth Security</span>
        <span class="badge ok" id="alert-auth-badge">–</span>
      </div>
      <div class="alert" id="alert-source">
        <span class="title">Log Source</span>
        <span class="badge ok" id="alert-source-badge">–</span>
      </div>
    </div>
  </div>

  <div class="card" style="grid-column:1/span 2">
    <h2>📊 Today — Mail Flow</h2>
    <div class="kpis">
      <div class="kpi"><div class="v" id="incoming">–</div><div class="l">Incoming</div></div>
      <div class="kpi"><div class="v" id="sent">–</div><div class="l">Sent</div></div>
      <div class="kpi"><div class="v" id="failed_delivery">–</div><div class="l">Failed</div></div>
      <div class="kpi"><div class="v" id="rejected">–</div><div class="l">Rejected</div></div>
      <div class="kpi"><div class="v" id="spam_virus">–</div><div class="l">Spam/Virus</div></div>
      <div class="kpi"><div class="v" id="quota_fail">–</div><div class="l">Quota</div></div>
      <div class="kpi"><div class="v" id="authfail">–</div><div class="l">Auth Fail</div></div>
      <div class="kpi"><div class="v" id="success_rate">–</div><div class="l">Success %</div></div>
    </div>
    <div class="row"><small>Date:</small><code id="date">–</code></div>
  </div>

  <div class="card">
    <h2>📦 Queue</h2>
    <div class="kpis">
      <div class="kpi"><div class="v" id="q_total">–</div><div class="l">Total</div></div>
      <div class="kpi"><div class="v" id="q_deferred">–</div><div class="l">Deferred</div></div>
    </div>
    <div class="row"><small>Status:</small><span class="badge" id="q_status">…</span></div>
  </div>

  <div class="card">
    <h2>👥 Sessions</h2>
    <div class="kpis">
      <div class="kpi"><div class="v" id="imap">–</div><div class="l">IMAP</div></div>
      <div class="kpi"><div class="v" id="pop3">–</div><div class="l">POP3</div></div>
      <div class="kpi"><div class="v" id="sess_total">–</div><div class="l">Total</div></div>
    </div>
  </div>

  <div class="card">
    <h2>💻 System</h2>
    <div class="row"><small>Uptime:</small><code id="uptime">–</code></div>
    <div class="row"><small>RAM:</small><code id="mem">–</code></div>
    <div class="row"><small>Disk /:</small><code id="disk">–</code></div>
    <div class="row"><small>Host:</small><code id="host">–</code></div>
  </div>

  <div class="card">
    <h2>📈 Live (60 min / 5m)</h2>
    <canvas id="liveChart"></canvas>
  </div>
  <div class="card">
    <h2>🕒 Today (by hour)</h2>
    <canvas id="dayChart"></canvas>
  </div>
  <div class="card">
    <h2>📅 Last 7 days</h2>
    <canvas id="weekChart"></canvas>
  </div>
  <div class="card">
    <h2>📆 Last 30 days</h2>
    <canvas id="monthChart"></canvas>
  </div>

  <div class="card">
    <h2>🍩 Today's Overview</h2>
    <canvas id="pieToday"></canvas>
  </div>
  <div class="card">
    <h2>🍩 Today's Errors</h2>
    <canvas id="pieErrors"></canvas>
  </div>

  <div class="card" style="grid-column:1/span 2">
    <h2>🧪 Diagnostics</h2>
    <div class="row"><small>Log source:</small><code id="diag-source">–</code></div>
    <div class="row"><small>Files:</small><code id="diag-files">–</code></div>
    <div class="row"><small>Recent rows (60s):</small><code id="diag-recent">–</code></div>
    <div class="row"><small>Bins:</small><code id="diag-bins">–</code></div>
    <div class="row"><small>Note:</small><code id="diag-note">–</code></div>
    <ul class="mini" id="diag-warn"></ul>
  </div>

  <div class="card" style="grid-column: span 2;">
      <h2>📊 Top Senders & Recipients (Today)</h2>
      <div class="table-container">
          <div class="table-wrapper">
              <h3>Top Senders</h3>
              <table class="mini-table"><thead><tr><th>Email</th><th>Count</th></tr></thead><tbody id="top-senders-day"></tbody></table>
          </div>
          <div class="table-wrapper">
              <h3>Top Recipients</h3>
              <table class="mini-table"><thead><tr><th>Email</th><th>Count</th></tr></thead><tbody id="top-recipients-day"></tbody></table>
          </div>
      </div>
  </div>
  <div class="card" style="grid-column: span 2;">
      <h2>📅 Top Senders & Recipients (Week)</h2>
      <div class="table-container">
          <div class="table-wrapper">
              <h3>Top Senders</h3>
              <table class="mini-table"><thead><tr><th>Email</th><th>Count</th></tr></thead><tbody id="top-senders-week"></tbody></table>
          </div>
          <div class="table-wrapper">
              <h3>Top Recipients</h3>
              <table class="mini-table"><thead><tr><th>Email</th><th>Count</th></tr></thead><tbody id="top-recipients-week"></tbody></table>
          </div>
      </div>
  </div>
  <div class="card" style="grid-column: span 2;">
      <h2>📆 Top Senders & Recipients (Month)</h2>
      <div class="table-container">
          <div class="table-wrapper">
              <h3>Top Senders</h3>
              <table class="mini-table"><thead><tr><th>Email</th><th>Count</th></tr></thead><tbody id="top-senders-month"></tbody></table>
          </div>
          <div class="table-wrapper">
              <h3>Top Recipients</h3>
              <table class="mini-table"><thead><tr><th>Email</th><th>Count</th></tr></thead><tbody id="top-recipients-month"></tbody></table>
          </div>
      </div>
  </div>

</div>

<div class="footer">Updated: <span id="updated">–</span> · <a href="?api=health" target="_blank" style="color:#4cc9f0">health</a> · <a href="?api=source" target="_blank" style="color:#4cc9f0">source</a></div>

<script>
const $=id=>document.getElementById(id);
async function j(api){ const r = await fetch('?api='+api,{cache:'no-store'}); return r.json(); }

Chart.defaults.color='#9aa6b2';
Chart.defaults.borderColor='#1a1f29';

function makeLine(ctx,labels,datasets){
  return new Chart(ctx,{type:'line',data:{labels,datasets},options:{
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{labels:{color:'#e6edf3',font:{size:10}}}},
    elements:{line:{tension:.3}},
    scales:{x:{ticks:{font:{size:9}}},y:{beginAtZero:true,ticks:{font:{size:9}}}}
  }});
}
function makeBar(ctx,labels,datasets){
  return new Chart(ctx,{type:'bar',data:{labels,datasets},options:{
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{labels:{color:'#e6edf3',font:{size:10}}}},
    scales:{x:{stacked:true,ticks:{font:{size:9}}},y:{stacked:true,beginAtZero:true,ticks:{font:{size:9}}}}
  }});
}
function makePie(ctx,labels,data,colors){
  return new Chart(ctx,{type:'doughnut',data:{labels,datasets:[{data,backgroundColor:colors}]},options:{
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{labels:{color:'#e6edf3',font:{size:10}}}}
  }});
}
function ds(label,data,color){return{label,data,borderColor:color,backgroundColor:color+'33',borderWidth:2,fill:false,tension:.3};}

let charts={};
function setBadge(el,level,text){ el.className='badge ' + (level==='ok'?'ok':level==='warn'?'warn':'err'); el.textContent=text; }

async function refreshHealth(){
  try{
    const h = await j('health');
    const src = h.source || {};
    const files = (h.readable_files||[]).join(', ');
    $('diag-source').textContent = src.glob || 'journal';
    $('diag-files').textContent = files || '–';
    $('diag-recent').textContent = h.recent_60s_rows ?? '–';
    $('diag-bins').textContent = Object.entries(h.bins_present||{}).map(([k,v])=>k+':' + (v?'✓':'×')).join(' ');
    $('diag-note').textContent = h.note || '–';
    const warnList = (h.warnings||[]).filter(Boolean).map(w=>'<li>'+w+'</li>').join('');
    $('diag-warn').innerHTML = warnList || '<li style="color:#9ae6b4">no warnings</li>';

    const srcBadge = $('alert-source-badge');
    if ((h.readable_files||[]).length>0) setBadge(srcBadge,'ok','files');
    else setBadge(srcBadge,'warn','journal');
  }catch(e){console.error(e);}
}

async function refreshKPIs(){
  try{
    const [today, queue, sessions, totals, system] = await Promise.all([
      j('today'), j('queue'), j('sessions'), j('totals'), j('system')
    ]);
    $('date').textContent = today.date;
    $('incoming').textContent = today.incoming;
    $('sent').textContent = today.sent;
    $('failed_delivery').textContent = today.failed_delivery;
    $('rejected').textContent = today.rejected;
    $('spam_virus').textContent = today.spam_virus;
    $('quota_fail').textContent = today.quota_fail;
    $('authfail').textContent = today.auth_fail;
    $('success_rate').textContent = (today.success_rate||0) + '%';

    $('q_total').textContent = queue.total ?? '–';
    $('q_deferred').textContent = queue.deferred ?? '–';
    const badge = $('q_status');
    if (queue.ok) {
      const t = queue.total || 0;
      badge.textContent = (t===0)?'Empty':(t<20?'Low':(t<200?'Moderate':'High'));
      badge.className = 'badge ' + (t===0?'ok':(t<200?'warn':'err'));
    } else { badge.textContent='Error'; badge.className='badge err'; }

    $('imap').textContent = sessions.imap ?? '–';
    $('pop3').textContent = sessions.pop3 ?? '–';
    $('sess_total').textContent = sessions.total ?? '–';

    $('uptime').textContent = system.uptime ?? '–';
    const m = system.mem_mb || {};
    $('mem').textContent = (m.used ?? '?') + ' / ' + (m.total ?? '?') + ' MB';
    const d = system.disk_root || {};
    $('disk').textContent = `${d.used ?? '?'} / ${d.size ?? '?'} (${d.usep ?? '?'})`;
    $('host').textContent = system.host ?? '–';

    const mailBadge = $('alert-mail-badge');
    const authBadge = $('alert-auth-badge');
    const queueBadge = $('alert-queue-badge');

    const fail = (today.failed_delivery||0) + (today.rejected||0) + (today.spam_virus||0);
    const inc  = (today.incoming||0) || 1;
    const fr   = fail / inc;
    if (fr < 0.05) setBadge(mailBadge,'ok','OK');
    else if (fr < 0.15) setBadge(mailBadge,'warn','Warn');
    else setBadge(mailBadge,'err','Incident');

    const af = today.auth_fail||0;
    if (af < 50) setBadge(authBadge,'ok','Calm');
    else if (af < 300) setBadge(authBadge,'warn','Noisy');
    else setBadge(authBadge,'err','Attack?');

    const qt = queue.total||0;
    if (qt===0) setBadge(queueBadge,'ok','Empty');
    else if (qt<200) setBadge(queueBadge,'warn',String(qt));
    else setBadge(queueBadge,'err',String(qt));

    $('updated').textContent = new Date().toLocaleTimeString('en-US');
  }catch(e){console.error(e);}
}

async function refreshCharts(){
  try{
    const [live, day, week, month, todayKpis] = await Promise.all([
      j('series_live'), j('series_today'), j('series_week'), j('series_month'), j('today')
    ]);

    const liveDs = [
      ds('Incoming', live.incoming, '#4cc9f0'),
      ds('Sent', live.sent, '#90ee90'),
      ds('Failed', live.failed_delivery, '#ef476f'),
      ds('Quota', live.quota_fail, '#fb923c'),
      ds('Rejected', live.rejected, '#ffd166'),
      ds('Spam/Virus', live.spam_virus, '#a78bfa'),
      ds('Auth Fail', live.auth_fail, '#f472b6'),
    ];
    if(!charts.live){ charts.live = makeLine($('liveChart'), live.labels, liveDs); }
    else { charts.live.data.labels=live.labels; charts.live.data.datasets.forEach((d,i)=>d.data=liveDs[i].data); charts.live.update('none'); }

    const dayDs = [
      {label:'Incoming', data: day.incoming, backgroundColor:'#4cc9f0', stack:'a'},
      {label:'Sent', data: day.sent, backgroundColor:'#90ee90', stack:'a'},
      {label:'Failed', data: day.failed_delivery, backgroundColor:'#ef476f', stack:'a'},
      {label:'Quota', data: day.quota_fail, backgroundColor:'#fb923c', stack:'a'},
      {label:'Rejected', data: day.rejected, backgroundColor:'#ffd166', stack:'a'},
      {label:'Spam/Virus', data: day.spam_virus, backgroundColor:'#a78bfa', stack:'a'},
    ];
    if(!charts.day){ charts.day = makeBar($('dayChart'), day.labels, dayDs); }
    else { charts.day.data.labels=day.labels; charts.day.data.datasets.forEach((d,i)=>d.data=dayDs[i].data); charts.day.update('none'); }

    const weekDs = [
      {label:'Incoming', data: week.incoming, backgroundColor:'#4cc9f0', stack:'a'},
      {label:'Sent', data: week.sent, backgroundColor:'#90ee90', stack:'a'},
      {label:'Failed', data: week.failed_delivery, backgroundColor:'#ef476f', stack:'a'},
      {label:'Quota', data: week.quota_fail, backgroundColor:'#fb923c', stack:'a'},
      {label:'Rejected', data: week.rejected, backgroundColor:'#ffd166', stack:'a'},
      {label:'Spam/Virus', data: week.spam_virus, backgroundColor:'#a78bfa', stack:'a'},
    ];
    if(!charts.week){ charts.week = makeBar($('weekChart'), week.labels, weekDs); }
    else { charts.week.data.labels=week.labels; charts.week.data.datasets.forEach((d,i)=>d.data=weekDs[i].data); charts.week.update('none'); }

    const monthDs = [
      ds('Incoming', month.incoming, '#4cc9f0'),
      ds('Sent', month.sent, '#90ee90'),
      ds('Failed', month.failed, '#ef476f'),
    ];
    if(!charts.month){ charts.month = makeLine($('monthChart'), month.labels, monthDs); }
    else { charts.month.data.labels=month.labels; charts.month.data.datasets.forEach((d,i)=>d.data=monthDs[i].data); charts.month.update('none'); }

    const pieTodayData=[todayKpis.incoming,todayKpis.sent,todayKpis.failed_delivery,todayKpis.rejected,todayKpis.spam_virus];
    const pieTodayLabels=['Incoming','Sent','Failed','Rejected','Spam/Virus'];
    const pieTodayColors=['#4cc9f0','#90ee90','#ef476f','#ffd166','#a78bfa'];

    const pieErrData=[todayKpis.rejected,todayKpis.spam_virus,todayKpis.quota_fail,todayKpis.auth_fail];
    const pieErrLabels=['Rejected','Spam/Virus','Quota/Full','Auth Fail'];
    const pieErrColors=['#ffd166','#a78bfa','#fb923c','#f472b6'];

    if(!charts.pieToday){ charts.pieToday = makePie($('pieToday'), pieTodayLabels, pieTodayData, pieTodayColors); }
    else { charts.pieToday.data.datasets[0].data = pieTodayData; charts.pieToday.update('none'); }

    if(!charts.pieErrors){ charts.pieErrors = makePie($('pieErrors'), pieErrLabels, pieErrData, pieErrColors); }
    else { charts.pieErrors.data.datasets[0].data = pieErrData; charts.pieErrors.update('none'); }

  }catch(e){ console.error(e); }
}

// NEW FUNCTION to refresh top talkers tables
async function refreshTopTalkers() {
    try {
        const [day, week, month] = await Promise.all([
            j('top_day'), j('top_week'), j('top_month')
        ]);

        const populateTable = (tbodyId, data) => {
            const tbody = $(tbodyId);
            tbody.innerHTML = '';
            if (Object.keys(data).length === 0) {
                tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--muted);">No data</td></tr>';
                return;
            }
            for (const [email, count] of Object.entries(data)) {
                const tr = document.createElement('tr');
                const tdEmail = document.createElement('td');
                tdEmail.textContent = email;
                const tdCount = document.createElement('td');
                tdCount.textContent = count;
                tr.appendChild(tdEmail);
                tr.appendChild(tdCount);
                tbody.appendChild(tr);
            }
        };

        populateTable('top-senders-day', day.senders);
        populateTable('top-recipients-day', day.recipients);

        populateTable('top-senders-week', week.senders);
        populateTable('top-recipients-week', week.recipients);

        populateTable('top-senders-month', month.senders);
        populateTable('top-recipients-month', month.recipients);

    } catch(e) { console.error('Error refreshing top talkers:', e); }
}

// Initial calls
refreshHealth();
refreshKPIs();
refreshCharts();
refreshTopTalkers(); // New initial call

// Intervals
setInterval(refreshHealth, 15000);
setInterval(refreshKPIs, 5000);
setInterval(refreshCharts, 30000);
setInterval(refreshTopTalkers, 60000); // New interval, e.g. every minute
</script>
</body>
</html>
