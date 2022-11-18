using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _dbContext;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext dbContext, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _dbContext = dbContext;
        }
        // [Authorize]
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await UserExists(registerDto.username)) return BadRequest("User already exists.");
            using var hmacsha = new HMACSHA512();

            var user = new AppUsers
            {
                UserName = registerDto.username.ToLower(),
                passwordHash = hmacsha.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                passwordSalt = hmacsha.Key
            };
            _dbContext.Add(user);
            await _dbContext.SaveChangesAsync();
            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
        // [Authorize]
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto logindto)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(x => x.UserName == logindto.Username.ToLower());
            if (user == null) return Unauthorized("Invalid username");
            using var hmacsha = new HMACSHA512(user.passwordSalt);
            var computedHash = hmacsha.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.passwordHash[i]) return Unauthorized("Incorrect password");
            }
            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
        private async Task<bool> UserExists(string username)
        {
            return await _dbContext.Users.AnyAsync(x => x.UserName == username.ToLower());
        }
    }
}