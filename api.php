<?php
declare(strict_types=1);

ini_set('pcre.jit', '0');
ini_set('session.cookie_httponly', '1');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_samesite', 'Lax');
session_set_cookie_params([
    'lifetime' => 3600,
    'path' => '/',
    'httponly' => true,
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'samesite' => 'Lax',
]);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';");

session_start();

if (!in_array($_SERVER['REQUEST_METHOD'] ?? '', ['GET', 'POST'], true)) {
    header('Allow: GET, POST');
    http_response_code(405);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $contentLength = filter_var($_SERVER['CONTENT_LENGTH'] ?? null, FILTER_VALIDATE_INT);
    if ($contentLength !== false && $contentLength > 65536) {
        http_response_code(413);
        exit;
    }
    if (!str_starts_with(strtolower($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json')) {
        http_response_code(415);
        exit;
    }

    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    if (is_string($origin) && $origin !== '') {
        $originParts = parse_url($origin);
        $requestScheme = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http';
        $requestHostParts = parse_url($requestScheme . '://' . (string) ($_SERVER['HTTP_HOST'] ?? ''));
        $defaultPort = $requestScheme === 'https' ? 443 : 80;
        if (!is_array($originParts)
            || !is_array($requestHostParts)
            || strtolower((string) ($originParts['scheme'] ?? '')) !== $requestScheme
            || strtolower((string) ($originParts['host'] ?? '')) !== strtolower((string) ($requestHostParts['host'] ?? ''))
            || (int) ($originParts['port'] ?? $defaultPort) !== (int) ($requestHostParts['port'] ?? $defaultPort)
            || isset($originParts['user'])
            || isset($originParts['pass'])
            || isset($originParts['query'])
            || isset($originParts['fragment'])
            || !in_array($originParts['path'] ?? '', ['', '/'], true)) {
            http_response_code(403);
            exit;
        }
    }
}

$applicationDirectory = realpath(__DIR__) ?: __DIR__;
$privateDirectory = dirname($applicationDirectory) . '/private';
if (!is_dir($privateDirectory) && !mkdir($privateDirectory, 0700, true) && !is_dir($privateDirectory)) {
    throw new RuntimeException('Impossible de créer le dossier privé.');
}
$resolvedPrivateDirectory = realpath($privateDirectory);
if ($resolvedPrivateDirectory === false
    || $resolvedPrivateDirectory === $applicationDirectory
    || str_starts_with($resolvedPrivateDirectory, $applicationDirectory . DIRECTORY_SEPARATOR)) {
    throw new RuntimeException('Le dossier privé doit être situé hors du dossier public.');
}
$privateDirectoryPermissions = fileperms($resolvedPrivateDirectory);
if ($privateDirectoryPermissions === false || ($privateDirectoryPermissions & 0077) !== 0) {
    throw new RuntimeException('Le dossier privé ne doit être accessible ni au groupe ni aux autres utilisateurs.');
}

$configPath = $privateDirectory . '/questionnaire.php';
if (is_link($configPath) || !is_file($configPath)) {
    throw new RuntimeException('La configuration privée est absente.');
}
$configPermissions = fileperms($configPath);
if ($configPermissions === false || ($configPermissions & 0027) !== 0) {
    throw new RuntimeException('Les permissions de la configuration privée sont trop ouvertes.');
}
$configuration = require $configPath;
$adminPasswordHash = $configuration['admin_password_hash'] ?? null;
if (!is_string($adminPasswordHash) || password_get_info($adminPasswordHash)['algo'] === null) {
    throw new RuntimeException('Le hash admin de la configuration privée est invalide.');
}

$databasePath = $privateDirectory . '/questionnaires.sqlite';
if (is_link($databasePath)) {
    throw new RuntimeException('Le chemin de la base privée ne doit pas être un lien symbolique.');
}
$legacyDatabasePath = $applicationDirectory . '/data/questionnaires.sqlite';
if (!is_file($databasePath) && is_file($legacyDatabasePath)) {
    if (is_link($legacyDatabasePath)) {
        throw new RuntimeException('L’ancienne base ne doit pas être un lien symbolique.');
    }
    if (!rename($legacyDatabasePath, $databasePath)) {
        throw new RuntimeException('Impossible de déplacer la base hors du dossier public.');
    }
    if (!chmod($databasePath, 0600)) {
        throw new RuntimeException('Impossible de protéger les permissions de l’ancienne base.');
    }
}

$database = new PDO('sqlite:' . $databasePath);
$database->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$database->exec('PRAGMA trusted_schema = OFF');
$database->exec('PRAGMA secure_delete = ON');
$database->exec('PRAGMA foreign_keys = ON');
$database->exec('PRAGMA busy_timeout = 5000');
$database->exec('PRAGMA synchronous = FULL');
if (!chmod($databasePath, 0600)) {
    throw new RuntimeException('Impossible de protéger les permissions du fichier de base.');
}
$database->exec('CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    prenom TEXT NOT NULL,
    nom_normalized TEXT NOT NULL DEFAULT \'\',
    prenom_normalized TEXT NOT NULL DEFAULT \'\',
    service TEXT NOT NULL,
    fonction TEXT NOT NULL DEFAULT \'\',
    anciennete TEXT NOT NULL,
    lateralite TEXT NOT NULL,
    nordic_json TEXT NOT NULL,
    psychosocial_json TEXT NOT NULL,
    activity_knowledge_json TEXT NOT NULL DEFAULT \'{}\',
    psychosocial_scale_version INTEGER NOT NULL DEFAULT 1,
    submission_token TEXT,
    consent_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)');
$columns = $database->query('PRAGMA table_info(responses)')->fetchAll(PDO::FETCH_COLUMN, 1);
if (!in_array('submission_token', $columns, true)) {
    $database->exec('ALTER TABLE responses ADD COLUMN submission_token TEXT');
}
if (!in_array('consent_at', $columns, true)) {
    $database->exec('ALTER TABLE responses ADD COLUMN consent_at TEXT');
}
if (!in_array('psychosocial_scale_version', $columns, true)) {
    $database->exec('ALTER TABLE responses ADD COLUMN psychosocial_scale_version INTEGER NOT NULL DEFAULT 1');
}
if (!in_array('fonction', $columns, true)) {
    $database->exec("ALTER TABLE responses ADD COLUMN fonction TEXT NOT NULL DEFAULT ''");
}
if (!in_array('nordic_comment', $columns, true)) {
    $database->exec("ALTER TABLE responses ADD COLUMN nordic_comment TEXT NOT NULL DEFAULT ''");
}
if (!in_array('psychosocial_comment', $columns, true)) {
    $database->exec("ALTER TABLE responses ADD COLUMN psychosocial_comment TEXT NOT NULL DEFAULT ''");
}
if (!in_array('activity_json', $columns, true)) {
    $database->exec("ALTER TABLE responses ADD COLUMN activity_json TEXT NOT NULL DEFAULT '{}'");
}
if (!in_array('activity_knowledge_json', $columns, true)) {
    $database->exec("ALTER TABLE responses ADD COLUMN activity_knowledge_json TEXT NOT NULL DEFAULT '{}'");
}
$normalizedNameColumnsMissing = !in_array('nom_normalized', $columns, true)
    || !in_array('prenom_normalized', $columns, true);
if (!in_array('nom_normalized', $columns, true)) {
    $database->exec("ALTER TABLE responses ADD COLUMN nom_normalized TEXT NOT NULL DEFAULT ''");
}
if (!in_array('prenom_normalized', $columns, true)) {
    $database->exec("ALTER TABLE responses ADD COLUMN prenom_normalized TEXT NOT NULL DEFAULT ''");
}
if ($normalizedNameColumnsMissing) {
    $database->beginTransaction();
    try {
        $rows = $database->query('SELECT id, nom, prenom FROM responses')->fetchAll(PDO::FETCH_ASSOC);
        $statement = $database->prepare('UPDATE responses
            SET nom_normalized = :nom_normalized, prenom_normalized = :prenom_normalized
            WHERE id = :id');
        foreach ($rows as $row) {
            $statement->execute([
                ':nom_normalized' => normalizeName($row['nom']),
                ':prenom_normalized' => normalizeName($row['prenom']),
                ':id' => $row['id'],
            ]);
        }
        $database->commit();
    } catch (Throwable $error) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        throw $error;
    }
}
$database->exec('CREATE INDEX IF NOT EXISTS responses_normalized_name_idx
    ON responses (nom_normalized, prenom_normalized)');
$database->exec('CREATE UNIQUE INDEX IF NOT EXISTS responses_submission_token_unique
    ON responses (submission_token) WHERE submission_token IS NOT NULL');
$database->exec('CREATE TABLE IF NOT EXISTS admin_login_limits (
    address_hash TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    window_started INTEGER NOT NULL
)');

function respond(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE);
    exit;
}

function consumeAdminLoginAttempt(PDO $database, string $adminPasswordHash): string
{
    $address = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $addressHash = hash_hmac('sha256', $address, $adminPasswordHash);
    $now = time();
    $windowSeconds = 900;
    $maximumAttempts = 5;

    $database->beginTransaction();
    try {
        $database->prepare('DELETE FROM admin_login_limits WHERE window_started <= :cutoff')
            ->execute([':cutoff' => $now - $windowSeconds]);
        $statement = $database->prepare('SELECT attempts, window_started FROM admin_login_limits WHERE address_hash = :address_hash');
        $statement->execute([':address_hash' => $addressHash]);
        $limit = $statement->fetch(PDO::FETCH_ASSOC);

        if ($limit !== false && (int) $limit['attempts'] >= $maximumAttempts) {
            $retryAfter = max(1, (int) $limit['window_started'] + $windowSeconds - $now);
            $database->commit();
            header('Retry-After: ' . $retryAfter);
            respond(['error' => 'Trop de tentatives. Réessayez plus tard.'], 429);
        }

        if ($limit === false) {
            $database->prepare('INSERT INTO admin_login_limits (address_hash, attempts, window_started) VALUES (:address_hash, 1, :window_started)')
                ->execute([':address_hash' => $addressHash, ':window_started' => $now]);
        } else {
            $database->prepare('UPDATE admin_login_limits SET attempts = attempts + 1 WHERE address_hash = :address_hash')
                ->execute([':address_hash' => $addressHash]);
        }
        $database->commit();
    } catch (Throwable $error) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        throw $error;
    }

    return $addressHash;
}

function normalizeName(string $value): string
{
    $value = trim($value);
    if (function_exists('mb_strtolower')) {
        return mb_strtolower($value, 'UTF-8');
    }

    return strtolower(strtr($value, [
        'À' => 'à', 'Á' => 'á', 'Â' => 'â', 'Ã' => 'ã', 'Ä' => 'ä', 'Å' => 'å', 'Æ' => 'æ',
        'Ç' => 'ç', 'È' => 'è', 'É' => 'é', 'Ê' => 'ê', 'Ë' => 'ë', 'Ì' => 'ì', 'Í' => 'í',
        'Î' => 'î', 'Ï' => 'ï', 'Ð' => 'ð', 'Ñ' => 'ñ', 'Ò' => 'ò', 'Ó' => 'ó', 'Ô' => 'ô',
        'Õ' => 'õ', 'Ö' => 'ö', 'Ø' => 'ø', 'Ù' => 'ù', 'Ú' => 'ú', 'Û' => 'û', 'Ü' => 'ü',
        'Ý' => 'ý', 'Ÿ' => 'ÿ', 'Œ' => 'œ',
    ]));
}

function personExists(PDO $database, string $nom, string $prenom): bool
{
    $statement = $database->prepare('SELECT 1 FROM responses
        WHERE nom_normalized = :nom_normalized AND prenom_normalized = :prenom_normalized
        LIMIT 1');
    $statement->execute([
        ':nom_normalized' => normalizeName($nom),
        ':prenom_normalized' => normalizeName($prenom),
    ]);

    return $statement->fetchColumn() !== false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawInput = file_get_contents('php://input', false, null, 0, 65537);
    if ($rawInput === false || strlen($rawInput) > 65536) {
        respond(['error' => 'La requête est invalide ou trop volumineuse.'], 413);
    }
    $input = json_decode($rawInput, true);
    if (!is_array($input)) {
        respond(['error' => 'Données JSON invalides.'], 400);
    }

    if (($input['action'] ?? '') === 'logout') {
        $_SESSION = [];
        session_destroy();
        setcookie(session_name(), '', [
            'expires' => time() - 3600,
            'path' => '/',
            'httponly' => true,
            'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'samesite' => 'Lax',
        ]);
        respond(['success' => true]);
    }

    if (isset($input['adminCode'])) {
        $submittedCode = (string) $input['adminCode'];
        $addressHash = consumeAdminLoginAttempt($database, $adminPasswordHash);
        if (password_verify($submittedCode, $adminPasswordHash)) {
            $database->prepare('DELETE FROM admin_login_limits WHERE address_hash = :address_hash')
                ->execute([':address_hash' => $addressHash]);
            session_regenerate_id(true);
            $_SESSION['admin'] = true;
            respond(['success' => true]);
        }

        respond(['error' => 'Code incorrect.'], 401);
    }

    if (($input['action'] ?? '') === 'checkName') {
        $nom = trim((string) ($input['nom'] ?? ''));
        $prenom = trim((string) ($input['prenom'] ?? ''));
        if ($nom === '' || $prenom === '') {
            respond(['error' => 'Veuillez renseigner votre nom et votre prénom.'], 422);
        }
        respond(['used' => personExists($database, $nom, $prenom)]);
    }

    foreach (['infos', 'nordic', 'psychosocial'] as $field) {
        if (!isset($input[$field]) || !is_array($input[$field])) {
            respond(['error' => 'Données de questionnaire incomplètes.'], 422);
        }
    }

    $infos = $input['infos'];
    foreach (['nom', 'prenom', 'service', 'anciennete', 'lateralite'] as $field) {
        if (!isset($infos[$field]) || trim((string) $infos[$field]) === '') {
            respond(['error' => 'Informations personnelles incomplètes.'], 422);
        }
    }
    $fonction = $infos['fonction'] ?? '';
    if (!is_string($fonction)
        || preg_match_all('/[\s\S]/u', $fonction, $fonctionCharacters) === false
        || count($fonctionCharacters[0]) > 120) {
        respond(['error' => 'La fonction est invalide ou trop longue.'], 422);
    }

    $activity = $input['activity'] ?? [
        'sportPracticed' => 'non_renseigne',
        'sportType' => '',
        'sessionsPerWeek' => null,
        'minutesPerSession' => null,
    ];
    if (!is_array($activity)
        || !in_array($activity['sportPracticed'] ?? null, ['oui', 'non', 'non_renseigne'], true)) {
        respond(['error' => 'La réponse sur l’activité physique est invalide.'], 422);
    }
    $sportType = $activity['sportType'] ?? '';
    if (!is_string($sportType)
        || preg_match_all('/[\s\S]/u', $sportType, $sportTypeCharacters) === false
        || count($sportTypeCharacters[0]) > 500) {
        respond(['error' => 'Le type d’activité physique est invalide ou trop long.'], 422);
    }
    $sessionsPerWeek = $activity['sessionsPerWeek'] ?? null;
    $minutesPerSession = $activity['minutesPerSession'] ?? null;
    if ($activity['sportPracticed'] === 'oui') {
        if (trim($sportType) === ''
            || (!is_int($sessionsPerWeek) && !(is_string($sessionsPerWeek) && ctype_digit($sessionsPerWeek)))
            || (int) $sessionsPerWeek < 1
            || (int) $sessionsPerWeek > 14) {
            respond(['error' => 'Précisez le type de sport et le nombre de séances hebdomadaires.'], 422);
        }
        if ($minutesPerSession !== null
            && ((!is_int($minutesPerSession) && !(is_string($minutesPerSession) && ctype_digit($minutesPerSession)))
                || (int) $minutesPerSession < 1
                || (int) $minutesPerSession > 600)) {
            respond(['error' => 'La durée de séance doit être comprise entre 1 et 600 minutes.'], 422);
        }
        $activity = [
            'sportPracticed' => 'oui',
            'sportType' => trim($sportType),
            'sessionsPerWeek' => (int) $sessionsPerWeek,
            'minutesPerSession' => $minutesPerSession === null ? null : (int) $minutesPerSession,
        ];
    } elseif ($activity['sportPracticed'] === 'non') {
        $activity = [
            'sportPracticed' => 'non',
            'sportType' => '',
            'sessionsPerWeek' => null,
            'minutesPerSession' => null,
        ];
    } else {
        $activity = [
            'sportPracticed' => 'non_renseigne',
            'sportType' => '',
            'sessionsPerWeek' => null,
            'minutesPerSession' => null,
        ];
    }

    $psychosocialScaleVersion = $input['psychosocialScaleVersion'] ?? 1;
    if (!is_int($psychosocialScaleVersion) || !in_array($psychosocialScaleVersion, [1, 2, 3, 4, 5, 6], true)) {
        respond(['error' => 'Version de l’échelle du questionnaire psychosocial invalide.'], 422);
    }
    $questionCount = $psychosocialScaleVersion >= 5
        ? ($psychosocialScaleVersion >= 6 ? 10 : 14)
        : ($psychosocialScaleVersion >= 4 ? 29 : ($psychosocialScaleVersion >= 3 ? 30 : 46));
    for ($questionNumber = 1; $questionNumber <= $questionCount; $questionNumber++) {
        $questionId = 'S' . $questionNumber;
        $answer = $input['psychosocial'][$questionId] ?? null;
        if ((!is_int($answer) && !(is_string($answer) && ctype_digit($answer)))
            || !in_array((int) $answer, $psychosocialScaleVersion >= 5 ? [0, 1, 2, 3, 4] : [1, 2, 3, 4], true)) {
            respond(['error' => 'Le questionnaire psychosocial est incomplet ou contient une réponse invalide.'], 422);
        }
    }

    $activityKnowledge = $input['activityKnowledge'] ?? [];
    if (!is_array($activityKnowledge)) {
        respond(['error' => 'Le questionnaire sur l’activité physique est invalide.'], 422);
    }
    if ($activityKnowledge !== []) {
        for ($questionNumber = 1; $questionNumber <= 20; $questionNumber++) {
            $questionId = 'Q' . $questionNumber;
            $answer = $activityKnowledge[$questionId] ?? null;
            if ((!is_int($answer) && !(is_string($answer) && ctype_digit($answer)))
                || (int) $answer < 0
                || (int) $answer > 3) {
                respond(['error' => 'Le questionnaire sur l’activité physique est incomplet ou contient une réponse invalide.'], 422);
            }
            $activityKnowledge[$questionId] = (int) $answer;
        }
    }

    $nordicZones = ['cou', 'epaules', 'coudes', 'poignets', 'haut_dos', 'bas_dos', 'hanches', 'genoux', 'chevilles'];
    $bilateralZones = ['epaules', 'coudes', 'poignets', 'genoux', 'chevilles'];
    foreach ($nordicZones as $zone) {
        $answer = $input['nordic'][$zone] ?? null;
        if (!is_array($answer) || !in_array($answer['hasPain12m'] ?? null, ['oui', 'non'], true)) {
            respond(['error' => 'Le questionnaire Nordique est incomplet.'], 422);
        }
        if (($answer['hasPain12m'] ?? null) === 'oui') {
            $intensity = $answer['intensity'] ?? null;
            $validIntensity = (is_int($intensity) || (is_string($intensity) && ctype_digit($intensity)))
                && (int) $intensity >= 1
                && (int) $intensity <= 10;
            if (in_array($zone, $bilateralZones, true)) {
                $side = $answer['side'] ?? null;
                $intensities = $answer['intensityBySide'] ?? null;
                $requiredSides = $side === 'deux'
                    ? ['gauche', 'droit']
                    : (in_array($side, ['gauche', 'droit'], true) ? [$side] : []);
                $validSideIntensities = is_array($intensities) && count($requiredSides) > 0;
                foreach ($requiredSides as $requiredSide) {
                    $sideIntensity = is_array($intensities) ? ($intensities[$requiredSide] ?? null) : null;
                    $validSideIntensities = $validSideIntensities
                        && (is_int($sideIntensity) || (is_string($sideIntensity) && ctype_digit($sideIntensity)))
                        && (int) $sideIntensity >= 1
                        && (int) $sideIntensity <= 10;
                }
                $validIntensity = $validIntensity && $validSideIntensities;
            }
            $validMoments = isset($answer['moments'])
                && is_array($answer['moments'])
                && count(array_filter($answer['moments'], static fn ($moment): bool => is_string($moment) && trim($moment) !== '')) > 0;
            $validFollowUps = in_array($answer['workHindrance'] ?? null, ['oui', 'non'], true)
                && in_array($answer['hasPain7d'] ?? null, ['oui', 'non'], true);
            if (!$validIntensity || !$validMoments || !$validFollowUps) {
                respond(['error' => 'Une réponse complémentaire du questionnaire Nordique est incomplète.'], 422);
            }
        }
    }

    $nordicComment = $input['nordicComment'] ?? '';
    $psychosocialComment = $input['psychosocialComment'] ?? '';
    foreach ([$nordicComment, $psychosocialComment] as $comment) {
        if (!is_string($comment)
            || preg_match_all('/[\s\S]/u', $comment, $characters) === false
            || count($characters[0]) > 5000) {
            respond(['error' => 'Un commentaire de questionnaire est invalide ou trop long.'], 422);
        }
    }

    $submissionToken = trim((string) ($input['submissionId'] ?? ''));
    if (!preg_match('/^[A-Za-z0-9-]{16,80}$/D', $submissionToken)) {
        respond(['error' => 'Identifiant de questionnaire invalide. Veuillez recommencer.'], 422);
    }
    if (($input['consent'] ?? false) !== true) {
        respond(['error' => 'Votre consentement au traitement des réponses est requis.'], 422);
    }

    $database->exec('BEGIN IMMEDIATE');
    try {
        $existingSubmission = $database->prepare('SELECT id, activity_knowledge_json FROM responses WHERE submission_token = :token');
        $existingSubmission->execute([':token' => $submissionToken]);
        $existing = $existingSubmission->fetch(PDO::FETCH_ASSOC);
        if ($existing !== false) {
            if ($activityKnowledge !== [] && in_array($existing['activity_knowledge_json'], ['', '{}'], true)) {
                $updateKnowledge = $database->prepare('UPDATE responses SET activity_knowledge_json = :answers WHERE id = :id');
                $updateKnowledge->execute([
                    ':answers' => json_encode($activityKnowledge, JSON_UNESCAPED_UNICODE),
                    ':id' => (int) $existing['id'],
                ]);
            }
            $database->exec('COMMIT');
            respond(['success' => true, 'id' => (int) $existing['id'], 'alreadySaved' => true]);
        }

        if (personExists($database, trim((string) $infos['nom']), trim((string) $infos['prenom']))) {
            $database->exec('ROLLBACK');
            respond(['error' => 'Ce nom et ce prénom ont déjà été utilisés pour un questionnaire.'], 409);
        }

        $statement = $database->prepare('INSERT INTO responses
            (nom, prenom, nom_normalized, prenom_normalized, service, fonction, anciennete, lateralite, nordic_json, psychosocial_json, activity_knowledge_json, psychosocial_scale_version, nordic_comment, psychosocial_comment, activity_json, submission_token, consent_at)
            VALUES (:nom, :prenom, :nom_normalized, :prenom_normalized, :service, :fonction, :anciennete, :lateralite, :nordic, :psychosocial, :activity_knowledge, :scale_version, :nordic_comment, :psychosocial_comment, :activity, :token, :consent_at)');
        $statement->execute([
            ':nom' => trim((string) $infos['nom']),
            ':prenom' => trim((string) $infos['prenom']),
            ':nom_normalized' => normalizeName(trim((string) $infos['nom'])),
            ':prenom_normalized' => normalizeName(trim((string) $infos['prenom'])),
            ':service' => trim((string) $infos['service']),
            ':fonction' => trim($fonction),
            ':anciennete' => trim((string) $infos['anciennete']),
            ':lateralite' => trim((string) $infos['lateralite']),
            ':nordic' => json_encode($input['nordic'], JSON_UNESCAPED_UNICODE),
            ':psychosocial' => json_encode($input['psychosocial'], JSON_UNESCAPED_UNICODE),
            ':activity_knowledge' => json_encode($activityKnowledge, JSON_UNESCAPED_UNICODE),
            ':scale_version' => $psychosocialScaleVersion,
            ':nordic_comment' => trim($nordicComment),
            ':psychosocial_comment' => trim($psychosocialComment),
            ':activity' => json_encode($activity, JSON_UNESCAPED_UNICODE),
            ':token' => $submissionToken,
            ':consent_at' => gmdate('c'),
        ]);
        $id = (int) $database->lastInsertId();
        $database->exec('COMMIT');
    } catch (Throwable $error) {
        $database->exec('ROLLBACK');
        throw $error;
    }
    respond(['success' => true, 'id' => $id], 201);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (($_SESSION['admin'] ?? false) !== true) {
        respond(['error' => 'Authentification requise.'], 401);
    }

    $rows = $database->query('SELECT id, nom, prenom, service, fonction, anciennete, lateralite,
        nordic_json, psychosocial_json, activity_knowledge_json, psychosocial_scale_version, nordic_comment, psychosocial_comment, activity_json, consent_at, created_at
        FROM responses ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as &$row) {
        $row['nordic'] = json_decode($row['nordic_json'], true);
        $row['psychosocial'] = json_decode($row['psychosocial_json'], true);
        $row['activityKnowledge'] = json_decode($row['activity_knowledge_json'], true) ?: [];
        $row['activity'] = json_decode($row['activity_json'], true) ?: [
            'sportPracticed' => 'non_renseigne',
            'sportType' => '',
            'sessionsPerWeek' => null,
            'minutesPerSession' => null,
        ];
        unset($row['nordic_json'], $row['psychosocial_json'], $row['activity_knowledge_json'], $row['activity_json']);
    }
    respond(['responses' => $rows]);
}

respond(['error' => 'Méthode non autorisée.'], 405);