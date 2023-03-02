using JwtWebApiTutorial.Services.UserService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtWebApiTutorial.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User User = new User();
        private readonly IConfiguration _configuration;
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;
            _userService = userService;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var UserName = _userService.GetMyName();
            return UserName;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> register(UserRegisterDto userDto)
        {
            CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

            User.Username = userDto.Username;
            User.PasswordHash = passwordHash;
            User.PasswordSalt = passwordSalt;

            User.Firstname = userDto.Firstname;
            User.Lastname = userDto.Lastname;
            User.Email = userDto.Email; 

            return Ok(User);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> login(UserDto userDto)
        {
            if (User.Username != userDto.Username)
            {
                return BadRequest("User Not Found.");
            }
            if (!VerifyPasswordHash(userDto.Password, User.PasswordHash, User.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }
            string token = CreateToken(User);

            var refreshToken = GenerateRefreshToken();
            SetRefreshToken(refreshToken);

            GetDataOfToken(token);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (!User.RefershToken.Equals(refreshToken))
            {
                return Unauthorized("Invalied Refresh Token.");
            }
            else if (User.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token expired.");
            }
            string token = CreateToken(User);
            
            var newRefreshToken = GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }

        //[HttpGet("DataOfToken")]
        //public  ActionResult<string> DataOfToken(string Token)
        //{
        //    GetDataOfToken(Token);
        //    return Ok("asd");
        //}



        private void GetDataOfToken(string Token)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken tokenS = handler.ReadToken(Token) as JwtSecurityToken;

            var oo = tokenS.Payload.First();
            var key = oo.Key;
            var value = oo.Value;
            var asdasdasd = tokenS.Claims.FirstOrDefault().Value;
            var profile = tokenS.Payload.Where(x => x.Value.Equals("Admin")).FirstOrDefault().Value;
            //JObject o = JObject.Parse(asdasdasd);
            //string cardType = o.SelectToken("$.roles." + "Rolename" + ".Type").ToString();
        }


        private RefershToken GenerateRefreshToken()
        {
            var refershToken = new RefershToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };
            return refershToken;
        }
        private void SetRefreshToken(RefershToken newRefershToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefershToken.Expires
            };
            Response.Cookies.Append("refreshToken", newRefershToken.Token, cookieOptions);

            User.RefershToken = newRefershToken.Token;
            User.TokenCreated = newRefershToken.Created;
            User.TokenExpires = newRefershToken.Expires;
        }
        private string CreateToken(User user)
        {
            List<object> data = new List<object>();
            
            data.Add(user.Firstname);
            data.Add(user.Lastname);
            data.Add(user.Email);
            
            string serialised = Newtonsoft.Json.JsonConvert.SerializeObject(data);

            IReadOnlyDictionary<string, object?> someData = new Dictionary<string, object?>();


            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, "Admin"),
                
            };

            

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            // Create HMAC by using "System.Security.Cryptography"
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(User.PasswordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
