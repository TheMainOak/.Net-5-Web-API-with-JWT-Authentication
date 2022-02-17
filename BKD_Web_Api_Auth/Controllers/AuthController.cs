using BKD_Web_Api_Auth.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace BKD_Web_Api_Auth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _config;

        public AuthController(IConfiguration config )
        {
            _config = config;
        }
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto u)
        {
            CreatePasswordHash(u.Password, out byte[] passwordHash, out byte[] passwordSalt); //Use the CreatePasswordHash method to generate a password hash and password salt from the string password

            user.Username = u.Username; //assign the static user variable a username
            user.PasswordHash = passwordHash; //assign the static user variable a password hash which was generated from the CreatePasswordHash method
            user.PasswordSalt = passwordSalt; //assign the static user variable a password salt which was generated from the CreatePasswordHash method

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto u) //Returned string is the JWT token
        {
            if(user.Username != u.Username) //Checks to see if user exists.
            {
                return BadRequest("User does not match any of our records.");
            }

            if(!VerifyPasswordHash(u.Password, user.PasswordHash, user.PasswordSalt)) //Confirms password is correct ussing VerifyPasswordHash
            {
                return BadRequest("Password is incorrect.");
            }

            string token = CreateNewToken(user);
                return Ok(token);
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt) //note the use of 'out', means we can use void method and no have to declare byte[] values for passwordHash and passwordSalt
        {
            using(var hmc = new HMACSHA512()) //Cryptography algorithm used to encrypt password.
            {
                passwordSalt = hmc.Key; //Assigns a key value to passwordSalt, because thats essentially what it is.
                passwordHash = hmc.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)); //generates a hash value for the password using the computeHash method which takes a bytes[] value as a parameter. The bytes[] value is generated from the password using the GetBytes method. 
            }
        }
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        } //Verifies password.
        private string CreateNewToken(User u) 
        {
            List<Claim> claims = new List<Claim>()  //Claims are information stored in the token describing the user that is authenticated i.e. could be username or ID or email etc. 
            {
                new Claim(ClaimTypes.Name, u.Username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
