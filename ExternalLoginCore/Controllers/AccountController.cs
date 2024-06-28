using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ExternalLoginCore.Controllers
{
    public class AccountController : Controller
    {
        #region Ctor

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        #endregion

        public IActionResult Login()
        {
            return View();
        }

        public IActionResult LoginFailed()
        {
            return View();
        }

        public IActionResult IsLocked()
        {
            return View();
        }

        public IActionResult NotAllowed()
        {
            return View();
        }

        [HttpPost]
        [Route("external-login")]
        public IActionResult ExternalLogin(string provider)
        {
            string redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account")!;
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl!);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [Route("external-response")]
        public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string? remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");

                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false, true);
            if (signInResult!.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }
            else if (signInResult.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(LoginFailed), "Account");
            }
            else if (signInResult.IsLockedOut)
            {
                return RedirectToAction(nameof(IsLocked), "Account");
            }
            else if (signInResult.IsNotAllowed)
            {
                return RedirectToAction(nameof(NotAllowed), "Account");
            }

            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var userName = string.Empty;
            if (email == null)
            {
                userName = info.Principal.FindFirstValue(ClaimTypes.Name);
                if (userName == null)
                {
                    return RedirectToAction(nameof(HomeController.Index), "Home");
                }
            }

            var user = new IdentityUser
            {
                UserName = email != null ? email.Split('@')[0].Replace(".", "") : userName.Replace(" ", ""),
                Email = email != null ? email : "new"+ userName.Replace(" ", "") + "Register@" + info.LoginProvider + ".com",
                EmailConfirmed = true
            };

            var createResult = await _userManager.CreateAsync(user);
            if (createResult.Succeeded)
            {
                createResult = await _userManager.AddLoginAsync(user, info);
                if (createResult.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return LocalRedirect(returnUrl);
                }
            }

            foreach (var error in createResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("sign-out")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
