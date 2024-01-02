using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestApiJwt.Dtos;
using TestApiJwt.Helpers;
using TestApiJwt.Services;

namespace TestApiJwt.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authservice;

        public AuthController(IAuthService Authservice)
        {
            _authservice = Authservice;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterDto Dto)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var result = await _authservice.RegisterAsync(Dto);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);

            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);
        } 

        [HttpPost("Token")]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestDto Dto)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var result = await _authservice.GetTokenAsync(Dto);

            if (!result.IsAuthenticated)
                return BadRequest(result.Message);
            if(!string.IsNullOrEmpty(result.RefreshToken))
            {
                SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);
            }
            return Ok(result);
        }

        [Authorize(Roles ="Admin")]
        [HttpPost("AddToRole")]
        public async Task<IActionResult> AddToRoleAsync([FromBody] AddUserToRoleDto Dto)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var result = await _authservice.AddUserToRole(Dto);

            if (!string.IsNullOrEmpty(result))
                return BadRequest(result);

            return Ok(Dto);
        }

        [HttpGet("refreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var result = await _authservice.RefreshTokenAsync(refreshToken);

            if (!result.IsAuthenticated)
                return BadRequest();

            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

            return Ok(result);
        }

        [HttpPost("revokeToken")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeToken Dto)
        {
            var token = Dto.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest("Token Is Required");

            var result = await _authservice.RevokeTokenAsync(token);
            
            if(!result)
                return BadRequest("Token Is Invalid");

            return Ok();

        }

        private void SetRefreshTokenInCookie(string refreshToken, DateTime expires)
        {
            var CokkieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expires.ToLocalTime()
            };
            Response.Cookies.Append("refreshToken", refreshToken, CokkieOptions);
        }
    }
}
