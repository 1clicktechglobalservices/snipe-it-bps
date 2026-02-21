<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\SamlNonce;
use App\Models\Setting;
use App\Models\User;
use App\Models\Ldap;
use App\Services\Saml;
use Com\Tecnick\Barcode\Barcode;
use Google2FA;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Log;
use Redirect;

/**
 * This controller handles authentication for the user, including local
 * database users and LDAP users.
 *
 * @author [A. Gianotto] [<snipe@snipe.net>]
 * @version    v1.0
 */
class LoginController extends Controller
{
    use ThrottlesLogins;

    // This tells the auth controller to use username instead of email address
    protected $username = 'username';

    /**
     * Where to redirect users after login / registration.
     *
     * @var string
     */
    protected $redirectTo = '/';

    /**
     * @var Saml
     */
    protected $saml;

    /**
     * Create a new authentication controller instance.
     *
     * @param Saml $saml
     *
     * @return void
     */
    public function __construct(Saml $saml)
    {
        parent::__construct();
        $this->middleware('guest', ['except' => ['logout', 'postTwoFactorAuth', 'getTwoFactorAuth', 'getTwoFactorEnroll']]);
        Session::put('backUrl', \URL::previous());
        $this->saml = $saml;
    }

    public function showLoginForm(Request $request)
    {
        $this->loginViaRemoteUser($request);
        $this->loginViaSaml($request);
        if (Auth::check()) {
            return redirect()->intended('/');
        }

        // Redirect to OAuth2 provider for authentication
        return redirect()->route('oauth.redirect');
    }

    /**
     * Disable direct username/password login — all auth goes through OAuth.
     */
    public function login(Request $request)
    {
        return redirect()->route('oauth.redirect');
    }

    /**
     * Log in a user by SAML
     *
     * @author Johnson Yi <jyi.dev@outlook.com>
     *
     * @since 5.0.0
     *
     * @param Request $request
     *
     * @return User
     *
     * @throws \Exception
     */
    private function loginViaSaml(Request $request)
    {
        $saml = $this->saml;
        $samlData = $request->session()->get('saml_login');

        if ($saml->isEnabled() && ! empty($samlData)) {

            try {
                $user = $saml->samlLogin($samlData);
                $notValidAfter = new \Carbon\Carbon(@$samlData['assertionNotOnOrAfter']);
                if(\Carbon::now()->greaterThanOrEqualTo($notValidAfter)) {
                    abort(400,"Expired SAML Assertion");
                }
                if(SamlNonce::where('nonce', @$samlData['nonce'])->count() > 0) {
                    abort(400,"Assertion has already been used");
                }
                Log::debug("okay, fine, this is a new nonce then. Good for you.");
                if (!is_null($user)) {
                    Auth::login($user);
                } else {
                    $username = $saml->getUsername();
                    Log::debug("SAML user '$username' could not be found in database.");
                    $request->session()->flash('error', trans('auth/message.signin.error'));
                    $saml->clearData();
                }

                if ($user = auth()->user()) {
                    $user->last_login = \Carbon::now();
                    $user->saveQuietly();
                }
                $s = new SamlNonce();
                $s->nonce = @$samlData['nonce'];
                $s->not_valid_after = $notValidAfter;
                $s->save();

            } catch (\Exception $e) {
                Log::debug('There was an error authenticating the SAML user: '.$e->getMessage());
                throw $e;
            }

        // Fallthrough with better logging
        } else {

            // Better logging
            if (empty($samlData)) {
                Log::debug("SAML page requested, but samlData seems empty.");
            }
        }



    }

    /**
     * Log in a user by LDAP
     *
     * @author Wes Hulette <jwhulette@gmail.com>
     *
     * @since 5.0.0
     *
     * @param Request $request
     *
     * @return User
     *
     * @throws \Exception
     */
    private function loginViaLdap(Request $request): User
    {
        Log::debug("Binding user to LDAP.");
         $ldap_user = Ldap::findAndBindUserLdap($request->input('username'), $request->input('password'));
         if (!$ldap_user) {
             Log::debug("LDAP user ".$request->input('username')." not found in LDAP or could not bind");
             throw new \Exception("Could not find user in LDAP directory");
         } else {
             Log::debug("LDAP user ".$request->input('username')." successfully bound to LDAP");
         }

         // Check if the user already exists in the database and was imported via LDAP
         $user = User::where('username', '=', $request->input('username'))->whereNull('deleted_at')->where('ldap_import', '=', 1)->where('activated', '=', '1')->first(); // FIXME - if we get more than one we should fail. and we sure about this ldap_import thing?
         Log::debug("Local auth lookup complete");

         // The user does not exist in the database. Try to get them from LDAP.
         // If user does not exist and authenticates successfully with LDAP we
         // will create it on the fly and sign in with default permissions
         if (!$user) {
             Log::debug("Local user ".$request->input('username')." does not exist");
             Log::debug("Creating local user ".$request->input('username'));

             if ($user = Ldap::createUserFromLdap($ldap_user, $request->input('password'))) {
                 Log::debug("Local user created.");
             } else {
                 Log::debug("Could not create local user.");
                 throw new \Exception("Could not create local user");
             }
             // If the user exists and they were imported from LDAP already
         } else {
             Log::debug("Local user ".$request->input('username')." exists in database. Updating existing user against LDAP.");

             $ldap_attr = Ldap::parseAndMapLdapAttributes($ldap_user);

            $user->password = $user->noPassword();
            if (Setting::getSettings()->ldap_pw_sync=='1') {
                $user->password = bcrypt($request->input('password'));
            }

            $user->last_login = \Carbon::now();
            $user->email = $ldap_attr['email'];
            $user->first_name = $ldap_attr['firstname'];
            $user->last_name = $ldap_attr['lastname']; //FIXME (or TODO?) - do we need to map additional fields that we now support? E.g. country, phone, etc.
            $user->saveQuietly();
        } // End if(!user)
        return $user;
    }

    private function loginViaRemoteUser(Request $request)
    {
        $header_name = Setting::getSettings()->login_remote_user_header_name ?: 'REMOTE_USER';
        $remote_user = $request->server($header_name);
        if (!isset($remote_user)) {
          $remote_user = $request->server('REDIRECT_'.$header_name);
        }
        if (Setting::getSettings()->login_remote_user_enabled == '1' && isset($remote_user) && ! empty($remote_user)) {
            Log::debug("Authenticating via HTTP header $header_name.");

            $strip_prefixes = [
                // IIS/AD
                // https://github.com/grokability/snipe-it/pull/5862
                '\\',

                // Google Cloud IAP
                // https://cloud.google.com/iap/docs/identity-howto#getting_the_users_identity_with_signed_headers
                'accounts.google.com:',
            ];

            $pos = 0;
            foreach ($strip_prefixes as $needle) {
                if (($pos = strpos($remote_user, $needle)) !== false) {
                    $pos += strlen($needle);
                    break;
                }
            }

            if ($pos > 0) {
                $remote_user = substr($remote_user, $pos);
            }

            try {
                $user = User::where('username', '=', $remote_user)->whereNull('deleted_at')->where('activated', '=', '1')->first();
                Log::debug('Remote user auth lookup complete');
                if (! is_null($user)) {
                    Auth::login($user, $request->input('remember'));
                }
            } catch (Exception $e) {
                Log::debug('There was an error authenticating the Remote user: '.$e->getMessage());
            }
        }
    }



    /**
     * Two factor enrollment page
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function getTwoFactorEnroll()
    {

        // Make sure the user is logged in
        if (! Auth::check()) {
            return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
        }

        $settings = Setting::getSettings();
        $user = auth()->user();

        // We wouldn't normally see this page if 2FA isn't enforced via the
        // \App\Http\Middleware\CheckForTwoFactor middleware AND if a device isn't enrolled,
        // but let's check anyway in case there's a browser history or back button thing.
        // While you can access this page directly, enrolling a device when 2FA isn't enforced
        // won't cause any harm.

        if (($user->two_factor_secret != '') && ($user->two_factor_enrolled == 1)) {
            return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.already_enrolled'));
        }

        $secret = Google2FA::generateSecretKey();
        $user->two_factor_secret = $secret;

        $barcode = new Barcode();
        $barcode_obj =
            $barcode->getBarcodeObj(
                'QRCODE',
                sprintf(
                    'otpauth://totp/%s:%s?secret=%s&issuer=Snipe-IT&period=30',
                    urlencode($settings->site_name),
                    urlencode($user->username),
                    urlencode($secret)
                ),
                300,
                300,
                'black',
                [-2, -2, -2, -2]
            );

        $user->saveQuietly(); // make sure to save *AFTER* displaying the barcode, or else we might save a two_factor_secret that we never actually displayed to the user if the barcode fails

        return view('auth.two_factor_enroll')->with('barcode_obj', $barcode_obj);
    }

    /**
     * Two factor code form page
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function getTwoFactorAuth()
    {
        // Check that the user is logged in
        if (! Auth::check()) {
            return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
        }

        $user = auth()->user();

        // Check whether there is a device enrolled.
        // This *should* be handled via the \App\Http\Middleware\CheckForTwoFactor middleware
        // but we're just making sure (in case someone edited the database directly, etc)
        if (($user->two_factor_secret == '') || ($user->two_factor_enrolled != 1)) {
            return redirect()->route('two-factor-enroll');
        }

        return view('auth.two_factor');
    }

    /**
     * Two factor code submission
     *
     * @param Request $request
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function postTwoFactorAuth(Request $request)
    {
        if (! Auth::check()) {
            return redirect()->route('login')->with('error', trans('auth/general.login_prompt'));
        }

        if (! $request->filled('two_factor_secret')) {
            return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.code_required'));
        }

        $user = auth()->user();
        $secret = $request->input('two_factor_secret');

        if (Google2FA::verifyKey($user->two_factor_secret, $secret)) {
            $user->two_factor_enrolled = 1;
            $user->last_login = \Carbon::now();
            $user->saveQuietly();
            $request->session()->put('2fa_authed', $user->id);

            return redirect()->route('home')->with('success', trans('auth/message.signin.success'));
        }

        return redirect()->route('two-factor')->with('error', trans('auth/message.two_factor.invalid_code'));
    }


    /**
     * Logout page.
     *
     * @param Request $request
     *
     * @return Illuminate\Http\RedirectResponse
     */
    public function logout(Request $request)
    {
        // Logout is only allowed with a http POST but we need to allow GET for SAML SLO
        $settings = Setting::getSettings();
        $saml = $this->saml;
        $samlLogout = $request->session()->get('saml_logout');
        $sloRedirectUrl = null;
        $sloRequestUrl = null;
    
        // Only allow GET if we are doing SAML SLO otherwise abort with 405
        if ($request->isMethod('GET') && !$samlLogout) {
            abort(405);
        }

        if ($saml->isEnabled()) {
            $auth = $saml->getAuth();
            $sloRedirectUrl = $request->session()->get('saml_slo_redirect_url');

            if (! empty($auth->getSLOurl()) && $settings->saml_slo == '1' && $saml->isAuthenticated() && empty($sloRedirectUrl)) {
                $sloRequestUrl = $auth->logout(null, [], $saml->getNameId(), $saml->getSessionIndex(), true, $saml->getNameIdFormat(), $saml->getNameIdNameQualifier(), $saml->getNameIdSPNameQualifier());
            }

            $saml->clearData();
        }

        if (! empty($sloRequestUrl)) {
            return redirect()->away($sloRequestUrl);
        }

        $request->session()->regenerate(true);
        $request->session()->forget('2fa_authed');

        if ($request->session()->has('password_hash_'.Auth::getDefaultDriver())){
            $request->session()->remove('password_hash_'.Auth::getDefaultDriver());
        }

        Auth::logout();

        if (! empty($sloRedirectUrl)) {
            return redirect()->away($sloRedirectUrl);
        }

        $customLogoutUrl = $settings->login_remote_user_custom_logout_url;
        if ($settings->login_remote_user_enabled == '1' && $customLogoutUrl != '') {
            return redirect()->away($customLogoutUrl);
        }

        return redirect()->route('login')->with(['success' => trans('auth/message.logout.success'), 'loggedout' => true]);
    }


    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'username' => 'required|not_array',
            'password' => 'required|not_array',
        ]);
    }


    public function username()
    {
        return 'username';
    }


    public function legacyAuthRedirect()
    {
        return redirect()->route('login');
    }

    public function redirectTo()
    {
        return Session::get('backUrl') ? Session::get('backUrl') : $this->redirectTo;
    }
}
