using BackendLoginRegister.Context;
using BackendLoginRegister.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace BackendLoginRegister.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("login")]  
        public async Task<IActionResult> Authenticate([FromBody] User userObj) //login validasyonu ve çıktıları
        {
            if (userObj == null)
            {
                return BadRequest();
            }
            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username && x.Password == userObj.Password);
            if (user == null)
            {
                return NotFound(new { Message = "User Not Found" });
            }
            else
            {

            user.Token = CreateJwt(user); //giriş başarılı olunca kullanıcı için token atanıyor.

            return Ok(new
            {
                Token = user.Token, //
                Message = "Login Success" 
            });
            }
        }
        [HttpPost("register")] 
        public async Task<IActionResult> RegisterUser([FromBody] User userObj) //register validasyonu ve çıktıları
        {
            if (userObj == null)
            {
                return BadRequest();
            }

            //check unique username
            if(await CheckUsernameExistAsync(userObj.Username))
            {
                return BadRequest(new { Message = "Username already exist" });
            }

            //check unique email
            if(await CheckEmailExistAsync(userObj.Email))
            {
                return BadRequest(new { Message = "Email already exist" });
            }

            //check password strength
            var pass = CheckPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
            {
                return BadRequest(new { Message = pass });
            }

            userObj.Role = "User"; //rol ataması
            userObj.Token = ""; //
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message = "User Registered"
            });
        }

        private async Task<bool> CheckUsernameExistAsync(string username)  //username unique check method
        {
            return await _authContext.Users.AnyAsync(x => x.Username == username);
        }

        private async Task<bool> CheckEmailExistAsync(string email)  //email unique check method
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();

            if (password.Length < 6)  //uzunluk kontrolü
            {
                sb.Append("Minimum password length should be 6 characters" + Environment.NewLine);
            }
            if (!(Regex.IsMatch(password, "[a-z]")  //şifre küçük harf, büyük harf ve rakam içermeli 
                && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password, "[0-9]")))
            {
                sb.Append("Password should include lowercase,uppercase and a number" + Environment.NewLine);
            }
            
            return sb.ToString();
        }  //password strenght check method
        
        
        private string CreateJwt(User user)  //json web token yaratıp ayarladığımız method.
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("SecretKeyValue12345"); //anahtarın boyutu şifreleme algoritmasından dolayı uzun olmalı. HS256
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),   //jwt şifrelemenin içerisinde rol bilgisi 
                new Claim(ClaimTypes.Name, user.Username) //ve username bilgisi içeriyor.
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        //getting all users. 
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
    }
}



