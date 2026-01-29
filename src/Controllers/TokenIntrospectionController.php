<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;

class TokenIntrospectionController
{
    private readonly Database $database;

    public function __construct(
        private readonly AccessTokenRepository $accessTokenRepository,
        ?Database $database = null,
    )
    {
        $this->database = $database ?? Database::getInstance();
    }

    public function __invoke(Request $request): Response
    {
        if ($request->getMethod() !== 'POST') {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Token introspection endpoint only accepts POST requests'
            ], 405);
        }

        $authHeader = $request->headers->get('Authorization');
        if (empty($authHeader)) {
            return new JsonResponse([
                'error' => 'invalid_client',
                'error_description' => 'Client authentication is required'
            ], 401);
        }

        if (!preg_match('/^Basic\s+(?P<credentials>[A-Za-z0-9+\/=]+)$/', $authHeader, $matches)) {
            return new JsonResponse([
                'error' => 'invalid_client',
                'error_description' => 'Invalid Authorization header - Basic auth required with client ID and client secret'
            ], 401);
        }

        $decoded = base64_decode($matches['credentials'], true);
        if ($decoded === false || !str_contains($decoded, ':')) {
            return new JsonResponse([
                'error' => 'invalid_client',
                'error_description' => 'Invalid Basic Auth payload format'
            ], 401);
        }

        [$clientId, $clientSecret] = explode(':', $decoded, 2);

        [$isAuthorized, $message] = $this->isAuthorizedBasicAuth($clientId, $clientSecret);

        if (!$isAuthorized) {
            return new JsonResponse([
                'error' => 'invalid_client',
                'error_description' => 'Client authorization failed: ' . $message
            ], 401);
        }

        $contentType = $request->headers->get('Content-Type');
        if (empty($contentType) || !str_contains($contentType, 'application/x-www-form-urlencoded')) {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Content-Type must be application/x-www-form-urlencoded'
            ], 400);
        }

        $token = $request->request->get('token');
        if (empty($token)) {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'Missing required parameter: token'
            ], 400);
        }

        return $this->introspectToken($token);
    }

    private function isAuthorizedBasicAuth(string $clientId, string $clientSecret): array
    {

        $db = $this->database;
        $result = $db->read(
            'SELECT id, secret, is_enabled, is_confidential FROM oidc_client WHERE id = :id', ['id' => $clientId]
        );

        $client = $result->fetch(\PDO::FETCH_ASSOC);

        if (!$client) {
            return [false,'Unknown client ID'];
        }


        if ((int)$client['is_enabled'] !== 1) {
            return [false,'Client disabled'];
        }

        if ((int)$client['is_confidential'] !== 1) {
            return [false,'Client not confidential'];
        }

        if (!hash_equals($client['secret'], $clientSecret)) {
            return [false,'Invalid client secret'];
        }

        return [true, "OK"];
    }

    private function introspectToken(string $token): JsonResponse
    {
        try {
            // JWT format: header.payload.signature
            $tokenParts = explode('.', $token);

            if (count($tokenParts) !== 3) {
                return new JsonResponse(['active' => false], 200);
            }

            $payload = json_decode(base64_decode(strtr($tokenParts[1], '-_', '+/')), true);

            if (!is_array($payload) || !isset($payload['jti'])) {
                return new JsonResponse(['active' => false], 200);
            }

            $tokenId = $payload['jti'];

            $accessToken = $this->accessTokenRepository->findById($tokenId);

            if (!$accessToken instanceof AccessTokenEntity) {
                return new JsonResponse(['active' => false], 200);
            }

            if ($accessToken->isRevoked()) {
                return new JsonResponse(['active' => false], 200);
            }

            if ($accessToken->getExpiryDateTime() < new \DateTimeImmutable()) {
                return new JsonResponse(['active' => false], 200);
            }

            $introspectionResponse = [
                'active' => true,
                'scope' => implode(' ', array_map(fn($scope) => $scope->getIdentifier(), $accessToken->getScopes())),
                'client_id' => $accessToken->getClient()->getIdentifier(),
                'token_type' => 'Bearer',
                'exp' => $accessToken->getExpiryDateTime()->getTimestamp(),
            ];

            if (isset($payload['iat'])) {
                $introspectionResponse['iat'] = $payload['iat'];
            }

            return new JsonResponse($introspectionResponse, 200);

        } catch (\Exception $e) {
            return new JsonResponse(['active' => false], 200);
        }
    }
}
