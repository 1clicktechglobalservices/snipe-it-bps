<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class OidcAuthController extends Controller
{
    private const SESSION_STATE_KEY = 'oidc_auth_state';

    public function redirectToOidc(Request $request): RedirectResponse
    {
        if (! $this->isEnabled()) {
            return redirect()->route('login');
        }

        try {
            $configuration = $this->getOpenIdConfiguration();
        } catch (Exception $exception) {
            Log::warning('OIDC discovery failed before redirect', ['error' => $exception->getMessage()]);

            return $this->failedLogin();
        }

        $state = Str::random(40);
        $request->session()->put(self::SESSION_STATE_KEY, $state);

        $params = [
            'response_type' => 'code',
            'client_id' => config('services.oidc.client_id'),
            'redirect_uri' => $this->redirectUri(),
            'scope' => $this->scopes(),
            'state' => $state,
            'nonce' => Str::random(40),
        ];

        $authorizationEndpoint = $configuration['authorization_endpoint'] ?? null;
        if (! is_string($authorizationEndpoint) || $authorizationEndpoint === '') {
            Log::warning('OIDC discovery response missing authorization_endpoint.');

            return $this->failedLogin();
        }

        return redirect()->away($authorizationEndpoint.'?'.http_build_query($params, '', '&', PHP_QUERY_RFC3986));
    }

    public function handleOidcCallback(Request $request): RedirectResponse
    {
        if (! $this->isEnabled()) {
            return redirect()->route('login');
        }

        if ($request->has('error')) {
            Log::warning('OIDC callback returned error', ['error' => $request->input('error')]);

            return $this->failedLogin();
        }

        $expectedState = $request->session()->pull(self::SESSION_STATE_KEY);
        $returnedState = $request->input('state');

        if (! is_string($expectedState) || $expectedState === '' || ! is_string($returnedState) || ! hash_equals($expectedState, $returnedState)) {
            Log::warning('OIDC callback state validation failed.');

            return $this->failedLogin();
        }

        $code = $request->input('code');
        if (! is_string($code) || $code === '') {
            Log::warning('OIDC callback did not include an authorization code.');

            return $this->failedLogin();
        }

        try {
            $configuration = $this->getOpenIdConfiguration();
            $tokenPayload = $this->exchangeCodeForTokens($configuration, $code);
            $claims = $this->fetchClaims($configuration, $tokenPayload);
        } catch (Exception $exception) {
            Log::warning('OIDC callback processing failed', ['error' => $exception->getMessage()]);

            return $this->failedLogin();
        }

        $user = $this->findUserFromClaims($claims);
        if (! $user) {
            Log::warning('OIDC user not found in Snipe-IT', ['claims' => Arr::only($claims, ['email', 'preferred_username', 'sub'])]);

            return $this->failedLogin();
        }

        if (! empty($claims['picture']) && is_string($claims['picture'])) {
            $user->update(['avatar' => $claims['picture']]);
        }

        Auth::login($user, true);
        $request->session()->regenerate();

        return redirect()->route('home');
    }

    private function exchangeCodeForTokens(array $configuration, string $code): array
    {
        $tokenEndpoint = $configuration['token_endpoint'] ?? null;
        if (! is_string($tokenEndpoint) || $tokenEndpoint === '') {
            throw new Exception('OIDC discovery response missing token endpoint.');
        }

        $response = Http::asForm()
            ->acceptJson()
            ->timeout(15)
            ->post($tokenEndpoint, [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUri(),
                'client_id' => config('services.oidc.client_id'),
                'client_secret' => config('services.oidc.client_secret'),
            ]);

        if ($response->failed()) {
            throw new Exception('OIDC token exchange failed: '.$response->status());
        }

        $payload = $response->json();
        if (! is_array($payload)) {
            throw new Exception('OIDC token response was not valid JSON.');
        }

        return $payload;
    }

    private function fetchClaims(array $configuration, array $tokenPayload): array
    {
        $accessToken = $tokenPayload['access_token'] ?? null;

        $userInfoEndpoint = $configuration['userinfo_endpoint'] ?? null;
        if (is_string($accessToken) && $accessToken !== '' && is_string($userInfoEndpoint) && $userInfoEndpoint !== '') {
            $response = Http::withToken($accessToken)
                ->acceptJson()
                ->timeout(15)
                ->get($userInfoEndpoint);

            if ($response->ok() && is_array($response->json())) {
                return $response->json();
            }
        }

        $idToken = $tokenPayload['id_token'] ?? null;
        if (is_string($idToken) && $idToken !== '') {
            $claims = $this->decodeJwtPayload($idToken);
            if (is_array($claims)) {
                return $claims;
            }
        }

        throw new Exception('Unable to extract OIDC claims from userinfo or id_token.');
    }

    private function findUserFromClaims(array $claims): ?User
    {
        $usernameClaim = config('services.oidc.username_claim', 'preferred_username');
        $claimIdentifier = $this->normalizeClaimValue($claims[$usernameClaim] ?? null);
        $email = $this->normalizeClaimValue($claims['email'] ?? null);
        $upn = $this->normalizeClaimValue($claims['upn'] ?? null);
        $sub = $this->normalizeClaimValue($claims['sub'] ?? null);

        $identifier = $claimIdentifier
            ?? $email
            ?? $upn
            ?? $sub;

        $candidateValues = array_values(array_unique(array_filter([
            $identifier,
            $email,
            $upn,
            $sub,
        ])));

        if (! empty($candidateValues)) {
            $user = User::query()
                ->whereIn('username', $candidateValues)
                ->orWhereIn('email', $candidateValues)
                ->orWhereIn('scim_externalid', $candidateValues)
                ->first();

            if ($user) {
                return $user;
            }
        }

        return null;
    }

    private function decodeJwtPayload(string $token): ?array
    {
        $parts = explode('.', $token);
        if (count($parts) < 2) {
            return null;
        }

        $payload = strtr($parts[1], '-_', '+/');
        $padding = strlen($payload) % 4;
        if ($padding > 0) {
            $payload .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode($payload, true);
        if ($decoded === false) {
            return null;
        }

        $json = json_decode($decoded, true);

        return is_array($json) ? $json : null;
    }

    private function getOpenIdConfiguration(): array
    {
        $discoveryUrl = $this->discoveryUrl();

        if (! $discoveryUrl) {
            throw new Exception('OIDC discovery URL is not configured.');
        }

        $cacheKey = 'oidc_discovery_'.sha1($discoveryUrl);

        return Cache::remember($cacheKey, now()->addMinutes(30), function () use ($discoveryUrl): array {
            $response = Http::acceptJson()
                ->timeout(10)
                ->get($discoveryUrl);

            if ($response->failed()) {
                throw new Exception('OIDC discovery request failed: '.$response->status());
            }

            $payload = $response->json();
            if (! is_array($payload)) {
                throw new Exception('OIDC discovery payload was not valid JSON.');
            }

            return $payload;
        });
    }

    private function discoveryUrl(): ?string
    {
        $discoveryUrl = trim((string) config('services.oidc.discovery_url', ''));
        if ($discoveryUrl !== '') {
            return $discoveryUrl;
        }

        $issuer = trim((string) config('services.oidc.issuer', ''));
        if ($issuer === '') {
            return null;
        }

        return rtrim($issuer, '/').'/.well-known/openid-configuration';
    }

    private function redirectUri(): string
    {
        $configured = trim((string) config('services.oidc.redirect', ''));

        return $configured !== '' ? $configured : config('app.url').'/oidc/callback';
    }

    private function scopes(): string
    {
        $scopes = trim((string) config('services.oidc.scopes', 'openid profile email'));

        return $scopes !== '' ? $scopes : 'openid profile email';
    }

    private function isEnabled(): bool
    {
        return (bool) config('services.oidc.enabled')
            && trim((string) config('services.oidc.client_id', '')) !== ''
            && trim((string) config('services.oidc.client_secret', '')) !== ''
            && $this->discoveryUrl() !== null;
    }

    private function normalizeClaimValue(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value !== '' ? $value : null;
    }

    private function failedLogin(): RedirectResponse
    {
        return redirect()->route('login')->withErrors([
            'username' => [
                trans('auth/general.oidc_login_failed'),
            ],
        ]);
    }
}
