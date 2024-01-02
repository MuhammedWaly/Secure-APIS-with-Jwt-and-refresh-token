using TestApiJwt.Dtos;
using TestApiJwt.Models;

namespace TestApiJwt.Services
{
    public interface IAuthService
    {
        Task<AuthModel> RegisterAsync(RegisterDto Dto);
        Task<AuthModel> GetTokenAsync(TokenRequestDto Dto);
        Task<AuthModel> RefreshTokenAsync(string Token);
        Task<bool> RevokeTokenAsync(string Token);
        Task<string> AddUserToRole(AddUserToRoleDto Dto);
    }
}
