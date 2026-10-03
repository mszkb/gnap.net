<?php
// Drives aaronpk/gnap-client-php through a complete GNAP redirect flow against a
// GNAP authorization server (RFC 9635 Sections 2-5), acting as the user's
// browser in between:
//
//   1. grant request (key by value, RSA-PSS-SHA512 httpsig proof), interact
//      start "redirect", finish "redirect" with a client nonce;
//   2. browser: follow interact.redirect through the AS's consent until the AS
//      redirects to the client's finish URI;
//   3. verify the interaction hash exactly as upstream public/redirect.php does;
//   4. continuation request with interact_ref (signed, covering Authorization).
//
// Usage: php driver.php <gnap-client-php checkout> <grant endpoint URI> <finish URI> [hash_method]
// Prints a JSON report; exits 0 only when an access token was issued.

if ($argc < 4) {
  fwrite(STDERR, "usage: php driver.php <gnap-client-php dir> <grant endpoint> <finish uri> [hash_method]\n");
  exit(2);
}

[$_, $clientDir, $grantEndpoint, $finishUri] = $argv;
$hashMethod = $argv[4] ?? 'sha3-512';
$phpHash = ['sha-256' => 'sha256', 'sha-512' => 'sha512', 'sha3-512' => 'sha3-512'][$hashMethod];

require $clientDir . '/vendor/autoload.php';

use phpseclib3\Crypt\RSA;

$report = ['grant_endpoint' => $grantEndpoint, 'hash_method' => $hashMethod];
function done(array $report, int $code) {
  echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
  exit($code);
}

// The upstream client loads its private key from a PEM file.
$keyFile = tempnam(sys_get_temp_dir(), 'gnap-php-interop');
file_put_contents($keyFile, RSA::createKey(2048)->toString('PKCS8'));
$_ENV['GNAP_AS_ENDPOINT'] = $grantEndpoint;
$client = new GNAPClient($keyFile, 'gnap-client-php interop', 'pss');

// 1. Grant request (upstream public/start.php, with a registered hash method name).
$nonce = bin2hex(random_bytes(10));
$start = $client->start([
  'interact' => [
    'start' => ['redirect'],
    'finish' => [
      'method' => 'redirect',
      'uri' => $finishUri,
      'nonce' => $nonce,
      'hash_method' => $hashMethod,
    ],
  ],
  'access_token' => [
    'access' => [
      ['type' => 'api', 'actions' => ['read']],
    ],
  ],
  'subject' => [
    'sub_id_formats' => ['opaque'],
  ],
]);
$report['grant_response'] = $start;
if (!isset($start['interact']['redirect'], $start['continue']['uri'])) {
  $report['result'] = 'grant request failed';
  done($report, 1);
}

// 2. The browser: follow redirects (keeping cookies) until the AS sends us to the finish URI.
$cookies = tempnam(sys_get_temp_dir(), 'gnap-php-cookies');
$url = $start['interact']['redirect'];
$callback = null;
for ($i = 0; $i < 10 && $callback === null; $i++) {
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_COOKIEJAR => $cookies,
    CURLOPT_COOKIEFILE => $cookies,
  ]);
  curl_exec($ch);
  $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
  $location = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
  curl_close($ch);
  $report['browser'][] = "$status $url";
  if (!$location) {
    $report['result'] = 'interaction did not redirect back to the client';
    done($report, 1);
  }
  if (str_starts_with($location, strtok($finishUri, '?'))) {
    $callback = $location;
  }
  $url = $location;
}
parse_str(parse_url($callback, PHP_URL_QUERY), $query);
$report['callback'] = $query;

// 3. Verify the interaction hash (upstream public/redirect.php).
$hashInput = $nonce . "\n"
  . $start['interact']['finish'] . "\n"
  . $query['interact_ref'] . "\n"
  . $grantEndpoint;
$hash = base64_urlencode(hash($phpHash, $hashInput, true));
$report['hash_valid'] = hash_equals($hash, $query['hash'] ?? '');
if (!$report['hash_valid']) {
  $report['result'] = 'interaction hash mismatch';
  done($report, 1);
}

// 4. Continue the grant with the interaction reference.
$final = $client->post($start['continue']['uri'], [
  'interact_ref' => $query['interact_ref'],
], [
  'Authorization' => 'GNAP ' . $start['continue']['access_token']['value'],
]);
$report['continue_response'] = $final;
if (!isset($final['access_token']['value'])) {
  $report['result'] = 'continuation did not issue an access token';
  done($report, 1);
}

$report['result'] = 'ok';
done($report, 0);
