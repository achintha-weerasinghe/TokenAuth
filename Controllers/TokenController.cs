using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using token_auth.Models.ViewModels;

namespace token_auth.Controllers
{
    [Route("api/[controller]")]
    public class TokenController : Controller
    {
        private IConfiguration _config;

        public TokenController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult CreateToken([FromBody]LoginViewModel login)
        {
            IActionResult response = Unauthorized();
            var user = Authenticate(login);

            if(user != null)
            {
                var tokenString = BuildToken(user);
                response = Ok(new { token = tokenString });
            }

            return response;
        }
        
        private string BuildToken(UserViewModel user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var claims = new[] {
                new Claim(type: JwtRegisteredClaimNames.Sub, value: user.Id.ToString()),
                new Claim(type: JwtRegisteredClaimNames.Email, value: user.Email),
                new Claim(type: JwtRegisteredClaimNames.Birthdate, value: user.Birthday.ToString("yyyy-MM-dd")),
                new Claim(type: JwtRegisteredClaimNames.Jti, value: Guid.NewGuid().ToString()),
                new Claim(type: "roles", value: JsonConvert.SerializeObject(user.Roles))
            };

            var token = new JwtSecurityToken(
                _config["JWT:Issuer"], 
                _config["JWT:Issuer"],
                claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds
                );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserViewModel Authenticate(LoginViewModel login)
        {
            UserViewModel user = null;

            if(login.Username == "achintha" && login.Password == "secret")
            {
                user = new UserViewModel 
                { 
                    Id = 1, 
                    Name = "Achintha Madumal", 
                    Email = "achinthamadumal@gmail.com", 
                    Birthday = DateTime.Now,
                    Roles = new string[] { "admin", "user" }
                };
            }

            return user;
        }
    }
}