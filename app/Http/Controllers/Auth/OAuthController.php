<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class OAuthController extends Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->middleware('guest', ['except' => []]);
    }

    /**
     * Redirect the user to the SSO login page.
     *
     * The provider uses a custom `url` parameter to know where to send
     * the user back after a successful login (our OAuth callback).
     */
    public function redirect(Request $request)
    {
        $state = Str::random(40);
        $request->session()->put('oauth_state', $state);

        $ssoLoginUrl = config('services.oauth.sso_login_url');

        $params = http_build_query([
            'success-redirect-uri'   => config('services.oauth.redirect_uri'),
        ]);

        return redirect()->away($ssoLoginUrl . '?' . $params);
    }

    /**
     * Handle the OAuth provider callback.
     */
    public function callback(Request $request)
    {
        $state        = $request->input('state');
        $sessionState = $request->session()->pull('oauth_state');

        if (empty($state) || $state !== $sessionState) {
            Log::warning('OAuth state mismatch during callback.');
            return redirect()->route('login')
                ->with('error', 'Invalid OAuth state. Please try again.');
        }

        if ($request->has('error')) {
            $errorDesc = $request->input('error_description', $request->input('error'));
            Log::error('OAuth provider returned error: ' . $errorDesc);
            return redirect()->route('login')
                ->with('error', 'OAuth authentication failed: ' . $errorDesc);
        }

        $code = $request->input('code');
        if (empty($code)) {
            return redirect()->route('login')
                ->with('error', 'No authorization code received from OAuth provider.');
        }

        // Exchange authorization code for tokens
        $tokenData = $this->exchangeCodeForToken($code);
        if (! $tokenData) {
            return redirect()->route('login')
                ->with('error', 'Failed to exchange authorization code for token.');
        }

        // Resolve user info from id_token or userinfo endpoint
        $userInfo = $this->resolveUserInfo($tokenData);
        if (! $userInfo) {
            return redirect()->route('login')
                ->with('error', 'Failed to retrieve user information from OAuth provider.');
        }

        // Find or create the local user record
        $user = $this->findOrCreateUser($userInfo);
        if (! $user) {
            return redirect()->route('login')
                ->with('error', 'Unable to authenticate user. Please contact your administrator.');
        }

        Auth::login($user);

        $user->last_login = Carbon::now();
        $user->saveQuietly();

        return redirect()->intended('/')->with('success', trans('auth/message.signin.success'));
    }

    /**
     * Exchange the authorization code for an access/id token.
     */
    private function exchangeCodeForToken(string $code): ?array
    {
        try {
            $response = Http::withoutVerifying()
                ->asForm()
                ->post(config('services.oauth.token_uri'), [
                    'grant_type'    => 'authorization_code',
                    'code'          => $code,
                    'redirect_uri'  => config('services.oauth.redirect_uri'),
                    'client_id'     => config('services.oauth.client_id'),
                    'client_secret' => config('services.oauth.client_secret'),
                ]);

            if ($response->failed()) {
                Log::error('OAuth token exchange failed. Status: ' . $response->status() . ' Body: ' . $response->body());
                return null;
            }

            return $response->json();
        } catch (\Exception $e) {
            Log::error('OAuth token exchange exception: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Resolve user info from id_token JWT payload or the userinfo endpoint.
     */
    private function resolveUserInfo(array $tokenData): ?array
    {
        // Prefer id_token JWT payload (no extra HTTP call)
        if (! empty($tokenData['id_token'])) {
            $payload = $this->decodeJwtPayload($tokenData['id_token']);
            if ($payload) {
                return $payload;
            }
        }

        // Fall back to userinfo endpoint
        if (! empty($tokenData['access_token'])) {
            try {
                $userInfoUrl = rtrim(config('services.oauth.issuer_uri'), '/') . '/oauth2/userinfo';
                $response    = Http::withoutVerifying()
                    ->withToken($tokenData['access_token'])
                    ->get($userInfoUrl);

                if ($response->successful()) {
                    return $response->json();
                }

                Log::warning('OAuth userinfo endpoint failed. Status: ' . $response->status());
            } catch (\Exception $e) {
                Log::warning('OAuth userinfo endpoint exception: ' . $e->getMessage());
            }
        }

        return null;
    }

    /**
     * Decode a JWT payload (without signature verification — issuer is trusted).
     */
    private function decodeJwtPayload(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }

        try {
            $payload = json_decode(
                base64_decode(strtr($parts[1], '-_', '+/')),
                true,
                512,
                JSON_THROW_ON_ERROR
            );
            return is_array($payload) ? $payload : null;
        } catch (\Exception $e) {
            Log::warning('JWT payload decode failed: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Find an existing user or create one from the OAuth user info claims.
     */
    private function findOrCreateUser(array $info): ?User
    {
        $email     = $info['email'] ?? null;
        $username  = $info['preferred_username'] ?? $info['sub'] ?? $email;
        $firstName = $info['given_name'] ?? (explode(' ', $info['name'] ?? '')[0] ?? '');
        $lastName  = $info['family_name'] ?? (count(explode(' ', $info['name'] ?? '')) > 1
            ? implode(' ', array_slice(explode(' ', $info['name']), 1))
            : '');

        if (empty($username) && empty($email)) {
            Log::error('OAuth user info is missing both username (sub/preferred_username) and email.');
            return null;
        }

        // Look up by username first, then by email
        $user = User::where('username', $username)->whereNull('deleted_at')->where('activated', 1)->first();

        if (! $user && $email) {
            $user = User::where('email', $email)->whereNull('deleted_at')->where('activated', 1)->first();
        }

        if ($user) {
            // Sync basic profile fields
            if ($email)     { $user->email      = $email; }
            if ($firstName) { $user->first_name = $firstName; }
            if ($lastName)  { $user->last_name  = $lastName; }
            $user->saveQuietly();
            return $user;
        }

        // Auto-provision a new user on first OAuth login
        $user             = new User();
        $user->username   = $username;
        $user->email      = $email ?? ($username . '@oauth.local');
        $user->password   = bcrypt(Str::random(40));
        $user->first_name = $firstName;
        $user->last_name  = $lastName;
        $user->activated  = 1;
        $user->save();

        Log::info("OAuth: auto-provisioned new user '{$username}'.");

        return $user;
    }
}
