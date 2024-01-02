using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TestApiJwt.Dtos;
using TestApiJwt.Helpers;
using TestApiJwt.Models;

namespace TestApiJwt.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _usermanger;
        private readonly RoleManager<IdentityRole> _rolemanger;
        private readonly Jwt _jwt;

        public AuthService(UserManager<ApplicationUser> usermanger, IOptions<Jwt> jwt, RoleManager<IdentityRole> rolemanger)
        {
            _usermanger = usermanger;
            _jwt = jwt.Value;
            _rolemanger = rolemanger;
        }
        public async Task<AuthModel> RegisterAsync(RegisterDto Dto)
        {
            if (await _usermanger.FindByEmailAsync(Dto.Email) != null)
            {
                return new AuthModel { Message = "Email is already registered" };

            }
            if (await _usermanger.FindByNameAsync(Dto.Username) != null)
            {
                return new AuthModel { Message = $"{Dto.Username} is already taken" };


            }
            var user = new ApplicationUser
            {
                UserName = Dto.Username,
                Email = Dto.Email,
                FirstName = Dto.firstName,
                LastName = Dto.LastName

            };
            var result = await _usermanger.CreateAsync(user, Dto.Password);
            if (!result.Succeeded)
            {
                string Errors = string.Empty;
                foreach (var Error in result.Errors)
                {
                    Errors += $"{Error.Description}, ";
                }
                return new AuthModel { Message = Errors };
            }
            await _usermanger.AddToRoleAsync(user, "User");
            var jwtSecurityToken = await CreateJwtTokenAsync(user);

            return new AuthModel
            {
                Email = user.Email,
                //ExpirDate = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Username = user.UserName,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
            };
        }



        public async Task<AuthModel> GetTokenAsync(TokenRequestDto Dto)
        {
            var authModel = new AuthModel();

            var user = await _usermanger.FindByEmailAsync(Dto.Email);

            if (user == null || !await _usermanger.CheckPasswordAsync(user, Dto.Password))
                return new AuthModel { Message = "Incorrect Email or password" };


            var RolesList = await _usermanger.GetRolesAsync(user);
            var jwtSecurityToken = await CreateJwtTokenAsync(user);

            authModel.Email = user.Email;
            //authModel.ExpirDate = jwtSecurityToken.ValidTo;
            authModel.IsAuthenticated = true;
            authModel.Roles = RolesList.ToList();
            authModel.Username = user.UserName;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            if (user.RefreshTokens.Any(t => t.IsActive))
            {
                var ActivRefreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
                authModel.RefreshToken = ActivRefreshToken.Token;
                authModel.RefreshTokenExpiration = ActivRefreshToken.ExpiresOn;
            }
            else
            {
                var refreshToken = GenerateRefreshToken();
                authModel.RefreshToken = refreshToken.Token;
                authModel.RefreshTokenExpiration = refreshToken.ExpiresOn;
                user.RefreshTokens.Add(refreshToken);
                await _usermanger.UpdateAsync(user);
            }

            return authModel;

        }






        public async Task<JwtSecurityToken> CreateJwtTokenAsync(ApplicationUser user)
        {
            var userClaims = await _usermanger.GetClaimsAsync(user);
            var roles = await _usermanger.GetRolesAsync(user);
            var roleClaims = new List<Claim>();


            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            //Claims Token
            var claims = new[]
            {
                  new Claim(JwtRegisteredClaimNames.Sub,user.UserName),
                  new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                  new Claim(JwtRegisteredClaimNames.Email, user.Email),
                  new Claim("uid",user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);


            var symetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.key));
            var SignInCredentials = new SigningCredentials(symetricSecurityKey, SecurityAlgorithms.HmacSha256);

            JwtSecurityToken mytoken = new JwtSecurityToken(
               issuer: _jwt.Issuer,//url web api
               audience: _jwt.Audience,//url consumer angular
               claims: claims,
               expires: DateTime.Now.AddHours(_jwt.Duration),
               signingCredentials: SignInCredentials
               );


            return mytoken;
        }

        public async Task<string> AddUserToRole(AddUserToRoleDto Dto)
        {
            var user = await _usermanger.FindByIdAsync(Dto.UserId);

            if (user == null || !await _rolemanger.RoleExistsAsync(Dto.Role))
                return "Invallid User or Role";

            if (await _usermanger.IsInRoleAsync(user, Dto.Role))
                return "User is already in this role";

            var result = await _usermanger.AddToRoleAsync(user, Dto.Role);

            return result.Succeeded ? string.Empty : "Something went wrong";
        }

        private RefreshToken GenerateRefreshToken()
        {
            var rondamNum = new byte[32];
            using var generator = new RNGCryptoServiceProvider();
            generator.GetBytes(rondamNum);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(rondamNum),
                ExpiresOn = DateTime.UtcNow.AddDays(10),
                CreatedOn = DateTime.UtcNow
            };
        }

        public async Task<AuthModel> RefreshTokenAsync(string Token)
        {
            var authModel = new AuthModel();
            var user = await _usermanger.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(u => u.Token == Token));
            if (user == null)
            {
                authModel.IsAuthenticated = false;
                authModel.Message = "Invalid Token";
                return authModel;
            }

            var refreshToken = user.RefreshTokens.Single(t => t.Token == Token);
            if (!refreshToken.IsActive)
            {
                authModel.IsAuthenticated = false;
                authModel.Message = "InActive Token";
                return authModel;
            }

            refreshToken.RevokedOn = DateTime.UtcNow;

            var newRedreshToken = GenerateRefreshToken();
            user.RefreshTokens.Add(newRedreshToken);
            await _usermanger.UpdateAsync(user);

            var JwtToken = await CreateJwtTokenAsync(user);
            var RolesList = await _usermanger.GetRolesAsync(user);
            authModel.Email = user.Email;
            authModel.IsAuthenticated = true;
            authModel.Roles = RolesList.ToList();
            authModel.Username = user.UserName;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(JwtToken);
            authModel.RefreshToken = newRedreshToken.Token;
            authModel.RefreshTokenExpiration = newRedreshToken.ExpiresOn;

            return authModel;
        }

        public async Task<bool> RevokeTokenAsync(string Token)
        {
            var user = await _usermanger.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(u => u.Token == Token));
            if (user == null)
                return false;

            var refreshToken = user.RefreshTokens.Single(t => t.Token == Token);
            if (!refreshToken.IsActive)
                return false;

            refreshToken.RevokedOn = DateTime.UtcNow;

            await _usermanger.UpdateAsync(user);
            return true;
        }
    }
}


