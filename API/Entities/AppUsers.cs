namespace API.Entities
{
    public class AppUsers
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public byte[] passwordHash { get; set; }
        public byte[] passwordSalt { get; set; }
    }
}